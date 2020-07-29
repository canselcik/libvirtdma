use libvirtdma::TypedRemotePtr;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UEComponent {
    // pub klass: RemotePtr,
    // pub monitor: RemotePtr,
    pub Object_m_CachedPtr: TypedRemotePtr<i32>,
}

pub type UEGameObject = UEComponent;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UEBehaviour {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UERigidbody {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UECollider {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UELODGroup {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UERenderer {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UEParticleSystem {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UEBounds {
    pub m_Center: UEVec3,
    pub m_Extents: UEVec3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UEVec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}
