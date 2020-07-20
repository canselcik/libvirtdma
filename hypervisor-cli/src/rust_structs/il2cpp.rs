use libvirtdma::{RemotePtr, TypedRemotePtr};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Il2CppObject {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TypedIl2CppObject<T> {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub _type: std::marker::PhantomData<T>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetStack<T> {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub _array: TypedRemotePtr<DotNetArray<T>>,
    pub _size: i32,
    pub _version: i32,
    pub _syncRoot: TypedRemotePtr<Il2CppObject>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetList<T> {
    pub methodTablePtr: u64,
    pub length: u64,
    pub firstElement: T,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetString {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub m_stringLength: i32,
    pub m_firstChar: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetArray<T> {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub bounds: TypedRemotePtr<Il2CppArrayBounds>,
    pub max_length: u64,
    pub m_Items: TypedRemotePtr<[T; 65535]>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Il2CppArrayBounds {
    pub length: u64,
    pub lower_bound: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetDict<T, U> {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub buckets: TypedRemotePtr<DotNetArray<i32>>,
    pub entries: TypedRemotePtr<DotNetArray<DotNetCollectionEntry<T, U>>>,
    pub count: i32,
    pub version: i32,
    pub freeList: i32,
    pub freeCount: i32,
    pub comparer: RemotePtr, // ptr to System_Collections_Generic_IEqualityComparer_TKey__o
    pub keys: RemotePtr, // ptr to System_Collections_Generic_Dictionary_KeyCollection_TKey__TValue__o
    pub values: RemotePtr, // ptr to System_Collections_Generic_Dictionary_ValueCollection_TKey__TValue__o
    pub _syncRoot: TypedRemotePtr<Il2CppObject>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DotNetCollectionEntry<T, U> {
    pub hashCode: i32,
    pub next: i32,
    pub key: TypedRemotePtr<TypedIl2CppObject<T>>,
    pub value: TypedRemotePtr<TypedIl2CppObject<U>>,
}
