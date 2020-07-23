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
    pub staticEntityRealm: RemotePtr, // 0x00
    pub _padding0: RemotePtr,         // 0x08
    pub _padding1: RemotePtr,         // 0x10
    pub _padding2: RemotePtr,         // 0x18
    pub entityDestroy: RemotePtr,     // to DeferredAction, 0x20
    pub postNetworkUpdateComponents: TypedRemotePtr<DotNetList<UEComponent>>, // 0x28
    pub parentEntityRef: TypedRemotePtr<EntityRef>, // [NonSerialized] 0x30
    pub _padding3: RemotePtr,         // 0x38
    pub children: TypedRemotePtr<DotNetList<BaseEntity>>, // [NonSerialized] 0x40
    pub prefabId: u32,                // 0x48
    pub globalBroadcast: bool, // 0x4C [If enabled the entity will send to everyone on the server - regardless of position]
    pub _padding4: [u8; 3],    // 0x4D
    pub net: RemotePtr,        // 0x50 to Networkable
    pub _padding5: RemotePtr,  // 0x58
    pub prefabName: TypedRemotePtr<DotNetString<8>>, // 0x60
    pub prefabNameWithoutExtension: TypedRemotePtr<DotNetString<8>>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GameObjectManager {
    pub client: RemotePtr,    // 0x00 ptr to game manager static
    pub _padding0: RemotePtr, // 0x08
    pub preProcessed: TypedRemotePtr<PrefabPreProcess>, // 0x10
    pub pool: TypedRemotePtr<PrefabPoolCollection>, // 0x18
    pub Clientside: bool,
    pub Serverside: bool,
}

pub type EntityRef = ResourceRef<BaseEntity>;
pub type GameObjectRef = ResourceRef<GameObject>;

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
pub struct ResourceRef<T> {
    pub guid: TypedRemotePtr<DotNetString<16>>,
    pub ResourceRef_1__cachedObject: TypedRemotePtr<T>,
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
    pub clientsideOnlyTypes: TypedRemotePtr<DotNetArray<RemotePtr>>, // to "Type" -- static
    pub serversideOnlyTypes: TypedRemotePtr<DotNetArray<RemotePtr>>, // to "Type" -- static
    pub isClientside: bool,
    pub isServerside: bool,
    pub isBundling: bool,
    pub prefabList: TypedRemotePtr<DotNetDict<DotNetString<16>, GameObject>>, // System_Collections_Generic_Dictionary_string__GameObject__o
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
