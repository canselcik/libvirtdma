#![allow(dead_code)]

pub type BaseNetworkableClassPtr = u64;
pub type MonitorPtr = u64;

#[repr(packed)]
#[derive(Clone, Copy, Debug)]
pub struct BaseNetworkable {
    pub(crate) klass: BaseNetworkableClassPtr,
    pub(crate) monitor: MonitorPtr,
    pub(crate) object_m_CachedPtr: u64,
    pub(crate) justCreated_k__BackingField: bool,
    pub(crate) entityDestroy_deferredAction: u64,
    pub(crate) postNetworkUpdateComponents_collectionsList: u64,
    pub(crate) parentEntityRef: u64,
    pub(crate) children_baseEntitylist: u64,
    pub(crate) prefabID: u32,
    pub(crate) globalBroadcast: bool,
    pub(crate) net_Network_Networkable_o: u64,
    pub(crate) isDestroyed_k__BackingField: bool,
    pub(crate) prefabNameStrRef: u64,
    pub(crate) prefabNameWithoutExtensionStrRef: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObjectManager {
    pub(crate) lastTaggedObject: *mut LastObjectBase,
    pub(crate) taggedObjects: *mut BaseObject,
    pub(crate) lastActiveObject: *mut LastObjectBase,
    pub(crate) activeObjects: *mut BaseObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseObject {
    pub(crate) pad_0x0000: [char; 0x8],
    pub(crate) nextObjectLink: *mut BaseObject,
    pub(crate) object: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LastObjectBase {
    pub(crate) pad_0x0000: [char; 0x10],
    pub(crate) lastObject: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EntityRef {
    pub(crate) ent_cached: u64, // BaseEntity_o*
    pub(crate) id_cached: u32,
}

#[repr(C)]
// #[derive(Clone, Copy, Debug)]
pub struct GameObject {
    pub(crate) pad_0x0000: [char; 0x8],
    pub(crate) m_instanceID: i32,
    pub(crate) pad_0x000C: [char; 0x24],
    pub(crate) m_label: i32,
    pub(crate) pad_0x0034: [char; 0x4],
    pub(crate) m_size: i32,
    pub(crate) pad_0x003C: [char; 0x4],
    pub(crate) m_capacity: i32,
    pub(crate) pad_0x0044: [char; 0x4],
    pub(crate) m_layer: i32,
    pub(crate) m_tag: i16,
    pub(crate) m_isActive: char,
    pub(crate) m_isActiveCached: char,
    pub(crate) m_isDestroying: char,
    pub(crate) m_isActivating: char,
    pub(crate) pad_0x0052: [char; 0x6],
    pub(crate) m_objectName: u64, // *String
}
