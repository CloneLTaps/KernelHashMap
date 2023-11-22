# Kernel HashMap

This HashMap implementation was based off of [this](https://github.com/DavidLeeds/hashmap) HashMap with modifications that make it work within the Windows Kernel along with adding
memory allocation and deallocation support to values along with a few other features. 

You can use this by either directly copying the files into your project or by using it as a lib inside your Kernel project. To do this inside of VS go to Properties -> Linker -> Input ->
Additional Dependencies and then add the path to the KernelHashMap lib file. Secondly, go to Properties -> C/C++ -> Additional Include Directories and add the path to the HashMap.h header file
(do not include the file in the path).

## How to initialize the HashMap
Firstly, define an instance of ``hashmap_base`` like so.
```
struct hashmap_base g_Button_Map;
```
Next, you will need to initialize your HashMap with a compare and a hash function ``hashmap_base_init``. Theres a default hash function included along with ones for integers and strings. The compare function is just used to determine
if two keys are equal. Keep in mind this must be done before you use your HashMap. Then if you want the HashMap to allocate memory for your keys use ``hashmap_base_set_key_alloc_funcs``. If you also want the HashMap to allocate 
memory for your values use ``hashmap_base_set_value_alloc_funcs``. If your HashMap is only used within the stack and you can guarantee the memory addresses of every key and value will be present, you won't need to allocate memory
for them. However, if you are using the Map as a global field and don't manually allocate memory for each key and value you will need to use the built in system for allocating and deallocating memory. When using the built in memory
system make sure you also include the size parameter in each function since this will be used to determine the amount of memory that will be created for each key and value.
```
    hashmap_base_init(&g_Button_Map, hashmap_int_hash_function, hashmap_int_compare_function);
    hashmap_base_set_key_alloc_funcs(&g_Button_Map, hashmap_generic_dup, hashmap_generic_free, sizeof(int));
    hashmap_base_set_value_alloc_funcs(&g_Button_Map, hashmap_generic_dup, hashmap_generic_free, sizeof(ControllerBinds));
```

## How to clean up the HashMap
To free all memory associated with the HashMap use the ``hashmap_base_cleanup`` function. To reset all entries inside the HashMap including the hash table use ``hashmap_base_reset``. To just clear all entries inside of the HashMap
use ``hashmap_base_clear`` and to remove a single key value pair use ``hashmap_base_remove``.

## How to use the HashMap
To add a key value pair into the HashMap use either ``hashmap_base_put`` or ``hashmap_base_put_replace``. The difference between these two is that ``hashmap_base_put_replace`` will replace the old value with the new value if that key
already exists. These both return an instance of NTSTATUS. You can check the success of said operation by doing the following. 
```
NTSTATUS status = STATUS_SUCCESS;
if (!NT_SUCCESS(status = hashmap_base_put_replace(&g_Button_Map, &pair->Key, &pair->Value))) {
    // Handle failure
}
```
The next important opperation is the ``hashmap_base_get`` function which takes in a pointer to your HashMap along with a pointer to your target key. Please ensure that the key you are passing in is the same size as the key the HashMap
holds otherwise you could expose extra memory and potentially corrupt the calculated keys hash.
```
    int makeCode = (int) data.MakeCode; // I need to pass in 'MakeCode' as a pointer and its natively a USHORT when 'hashmap_base_get' expects an int else our read will overflow
    PControllerBinds input = (PControllerBinds) hashmap_base_get(&g_Button_Map, &makeCode);
    if (!input) return; // This means the HashMap does not contain a mapping for this specific KeyCode.
```
