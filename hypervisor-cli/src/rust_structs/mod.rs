#![allow(non_snake_case, dead_code)]
use crate::rust_structs::il2cpp::{DotNetArray, DotNetDict, DotNetList, DotNetStack, DotNetString};
use crate::rust_structs::ue::{
    UEBehaviour, UEBounds, UECollider, UEComponent, UEGameObject, UELODGroup, UEParticleSystem,
    UERenderer, UERigidbody, UEVec3,
};
use libvirtdma::{RemotePtr, TypedRemotePtr};

pub mod il2cpp;
pub mod ue;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseNetworkable {
    // pub klass: RemotePtr,
    // pub monitor: RemotePtr,
    /// If enabled the entity will send to everyone on the server - regardless of position
    pub globalBroadcast: bool,
    pub net_Network_Networkable_o: RemotePtr, // ptr to Networkable
    pub prefabName: TypedRemotePtr<DotNetString<1>>,
    pub prefabNameWithoutExtension: TypedRemotePtr<DotNetString<1>>,
    pub serverEntities: RemotePtr, // static ptr to BaseNetworkable.EntityRealm -- kinda unsure
    pub isServersideEntity: bool,
    pub _limitedNetworking: bool,
    pub parentEntityRef: TypedRemotePtr<EntityRef>, // [NonSerialized]
    pub children: TypedRemotePtr<DotNetList<BaseEntity>>, // [NonSerialized]
    pub creationFrame: i32,
    pub isSpawned: bool,
    pub _NetworkCache: RemotePtr,          // ptr to MemoryStream
    pub EntityMemoryStreamPool: RemotePtr, // static ptr to Queue<MemoryStream>
    pub _SaveCache: RemotePtr,             // to MemoryStream
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObjectManager {
    // pub klass: RemotePtr,
    // pub monitor: RemotePtr,
    pub preProcessed: TypedRemotePtr<PrefabPreProcess>,
    pub pool: TypedRemotePtr<PrefabPoolCollection>,
    pub Clientside: bool,
    pub Serverside: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EntityRef {
    pub ent_cached: TypedRemotePtr<BaseEntity>,
    pub id_cached: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseEntity {
    // pub klass: RemotePtr,
    // pub monitor: RemotePtr,
    pub Object_m_CachedPtr: TypedRemotePtr<i32>,
    pub justCreated_k__BackingField: bool,
    pub entityDestroy_deferredAction: RemotePtr,
    pub postNetworkUpdateComponents: TypedRemotePtr<DotNetList<UEComponent>>,
    pub parentEntityRef: TypedRemotePtr<EntityRef>,
    pub children: TypedRemotePtr<DotNetList<BaseEntity>>,
    pub prefabID: u32,
    pub globalBroadcast: bool,
    pub net_Network_Networkable_o: RemotePtr,
    pub isDestroyed_k__BackingField: bool,
    pub prefabName: TypedRemotePtr<DotNetString<1>>,
    pub prefabNameWithoutExtension: TypedRemotePtr<DotNetString<1>>,
    pub ragdoll: RemotePtr,      // to Ragdoll_o
    pub positionLerp: RemotePtr, // to PositionLerp_o
    pub menuOptions: RemotePtr,  // to System_Collections_Generic_List_Option__o
    pub broadcastProtocol: u32,
    pub links: RemotePtr, // to System_Collections_Generic_List_EntityLink__o
    pub linkedToNeighbours: bool,
    pub updateParentingAction: RemotePtr, // to System_Action_o
    pub addedToParentEntity: TypedRemotePtr<BaseEntity>,
    pub itemSkin: RemotePtr,    // to ItemSkin_o
    pub entitySlots: RemotePtr, // to EntityRef_array
    pub triggers: RemotePtr,    // to System_Collections_Generic_List_TriggerBase__o
    pub isVisible: bool,
    pub isAnimatorVisible: bool,
    pub isShadowVisible: bool,
    pub localOccludee: OccludeeSphere,
    pub bounds: UEBounds,
    pub impactEffect: TypedRemotePtr<GameObjectRef>,
    pub enableSaving: bool,
    pub syncPosition: bool,
    pub model: RemotePtr, // to Model_o
    pub flags: i32,
    pub parentBone: u32,
    pub skinID: u64,
    pub _components: RemotePtr, // to EntityComponentBase_array
    pub _name: DotNetString<16>,
    pub _OwnerID_k__BackingField: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OccludeeSphere {
    pub id: i32,
    pub state: RemotePtr, // to OccludeeState_o
    pub sphere: OcclusionCullingSphere,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OcclusionCullingSphere {
    pub position: UEVec3,
    pub radius: f32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObjectRef {
    // pub klass: RemotePtr,
    // pub monitor: RemotePtr,
    pub guid: TypedRemotePtr<DotNetString<1>>,
    pub ResourceRef_1__cachedObject: TypedRemotePtr<UEGameObject>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefabPoolCollection {
    // pub klass: RemotePtr,   // PrefabPoolCollection_c
    // pub monitor: RemotePtr, // void*
    pub storage: TypedRemotePtr<DotNetDict<u32, PrefabPoolObject>>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefabPoolObject {
    // pub klass: RemotePtr,   // PrefabPool_c
    // pub monitor: RemotePtr, // void*
    pub stack: TypedRemotePtr<DotNetStack<PoolableObject>>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PoolableObject {
    // pub klass: RemotePtr,   // Poolable_c*
    // pub monitor: RemotePtr, // void*
    // pub Object_m_CachedPtr: TypedRemotePtr<i32>,
    pub prefabID: u32,
    pub behaviours: DotNetArray<UEBehaviour>,
    pub rigidbodies: DotNetArray<UERigidbody>,
    pub colliders: DotNetArray<UECollider>,
    pub lodgroups: DotNetArray<UELODGroup>,
    pub renderers: DotNetArray<UERenderer>,
    pub particles: DotNetArray<UEParticleSystem>,
    pub behaviourStates: DotNetArray<bool>,
    pub rigidbodyStates: DotNetArray<bool>,
    pub colliderStates: DotNetArray<bool>,
    pub lodgroupStates: DotNetArray<bool>,
    pub rendererStates: DotNetArray<bool>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefabPreProcess {
    // pub klass: RemotePtr,
    // pub monitor: RemotePtr,
    pub isClientside: bool,
    pub isServerside: bool,
    pub isBundling: bool,
    pub prefabList: TypedRemotePtr<DotNetDict<DotNetString<1>, GameObject>>, // System_Collections_Generic_Dictionary_string__GameObject__o
    pub destroyList: TypedRemotePtr<DotNetList<UEComponent>>,
    pub cleanupList: TypedRemotePtr<DotNetList<GameObject>>, // System_Collections_Generic_List_GameObject__o
}

// ===========

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseObject {
    pub pad_0x0000: libvirtdma::win::misc::Bytes8,
    pub nextObjectLink: *mut BaseObject,
    pub object: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LastObjectBase {
    pub pad_0x0000: libvirtdma::win::misc::Bytes16,
    pub lastObject: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObject {
    pub pad_0x0000: [u8; 0x8],
    pub m_instanceID: i32,
    pub pad_0x000C: libvirtdma::win::misc::Bytes36,
    pub m_label: i32,
    pub pad_0x0034: [u8; 0x4],
    pub m_size: i32,
    pub pad_0x003C: [u8; 0x4],
    pub m_capacity: i32,
    pub pad_0x0044: [u8; 0x4],
    pub m_layer: i32,
    pub m_tag: i16,
    pub m_isActive: u8,
    pub m_isActiveCached: u8,
    pub m_isDestroying: u8,
    pub m_isActivating: u8,
    pub pad_0x0052: [u8; 0x6],
    pub m_objectName: u64, // *String
}
