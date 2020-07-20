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
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub object_m_CachedPtr: RemotePtr,
    pub justCreated_k__BackingField: bool,
    pub entityDestroy_deferredAction: RemotePtr,
    pub postNetworkUpdateComponents: TypedRemotePtr<DotNetList<UEComponent>>,
    pub parentEntityRef: TypedRemotePtr<EntityRef>,
    pub children: TypedRemotePtr<DotNetList<BaseEntity>>,
    pub prefabID: u32,
    pub globalBroadcast: bool,
    pub net_Network_Networkable_o: RemotePtr,
    pub isDestroyed_k__BackingField: bool,
    pub prefabName: TypedRemotePtr<DotNetString>,
    pub prefabNameWithoutExtension: TypedRemotePtr<DotNetString>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObjectManager {
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
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
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
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
    pub prefabName: TypedRemotePtr<DotNetString>,
    pub prefabNameWithoutExtension: TypedRemotePtr<DotNetString>,
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
    pub _name: DotNetString,
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
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub guid: TypedRemotePtr<DotNetString>,
    pub ResourceRef_1__cachedObject: TypedRemotePtr<UEGameObject>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefabPoolCollection {
    pub klass: RemotePtr,   // PrefabPoolCollection_c
    pub monitor: RemotePtr, // void*
    pub storage: TypedRemotePtr<DotNetDict<u32, PrefabPoolObject>>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrefabPoolObject {
    pub klass: RemotePtr,   // PrefabPool_c
    pub monitor: RemotePtr, // void*
    pub stack: TypedRemotePtr<DotNetStack<PoolableObject>>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PoolableObject {
    pub klass: RemotePtr,   // Poolable_c*
    pub monitor: RemotePtr, // void*
    pub Object_m_CachedPtr: TypedRemotePtr<i32>,
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
    pub klass: RemotePtr,
    pub monitor: RemotePtr,
    pub isClientside: bool,
    pub isServerside: bool,
    pub isBundling: bool,
    pub prefabList: RemotePtr, // System_Collections_Generic_Dictionary_string__GameObject__o
    pub destroyList: RemotePtr, // System_Collections_Generic_List_Component__o
    pub cleanupList: RemotePtr, // System_Collections_Generic_List_GameObject__o
}

// ===========

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BaseObject {
    pub(crate) pad_0x0000: libvirtdma::win::misc::Bytes8,
    pub(crate) nextObjectLink: *mut BaseObject,
    pub(crate) object: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LastObjectBase {
    pub(crate) pad_0x0000: libvirtdma::win::misc::Bytes16,
    pub(crate) lastObject: *mut GameObject,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObject {
    pub(crate) pad_0x0000: [u8; 0x8],
    pub(crate) m_instanceID: i32,
    pub(crate) pad_0x000C: libvirtdma::win::misc::Bytes36,
    pub(crate) m_label: i32,
    pub(crate) pad_0x0034: [u8; 0x4],
    pub(crate) m_size: i32,
    pub(crate) pad_0x003C: [u8; 0x4],
    pub(crate) m_capacity: i32,
    pub(crate) pad_0x0044: [u8; 0x4],
    pub(crate) m_layer: i32,
    pub(crate) m_tag: i16,
    pub(crate) m_isActive: u8,
    pub(crate) m_isActiveCached: u8,
    pub(crate) m_isDestroying: u8,
    pub(crate) m_isActivating: u8,
    pub(crate) pad_0x0052: [u8; 0x6],
    pub(crate) m_objectName: u64, // *String
}
