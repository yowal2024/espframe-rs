//! Logical viewport handles for the existing runtime lifecycle. No Surface or Layer is created.
#![allow(non_snake_case)]
use crate::window::surface::{ANativeWindow, PrimaryDisplayQuery};
use crate::window::{DisplayInfo, Size, SurfaceComposerBackend, SurfaceHandle, WindowError};
use std::{collections::HashMap, ffi::CStr, ptr::NonNull};

pub struct SkiaWindowBackend {
    display: PrimaryDisplayQuery,
    handles: HashMap<usize, Box<u64>>,
    next: usize,
}
impl SkiaWindowBackend {
    pub fn ResolveProduction(skip: bool) -> Result<Self, WindowError> {
        let mut result = Self {
            display: PrimaryDisplayQuery::resolve()?,
            handles: HashMap::new(),
            next: 1,
        };
        result.Preflight(skip)?;
        Ok(result)
    }
    fn filter(&self, enabled: bool) -> Result<(), WindowError> {
        super::FILTER.store(enabled, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}
impl SurfaceComposerBackend for SkiaWindowBackend {
    fn Preflight(&mut self, skip: bool) -> Result<(), WindowError> {
        if !super::hooks::installed() {
            return Err(WindowError::Backend("Skia hooks not installed".into()));
        }
        self.filter(skip)
    }
    fn GetDisplayInfo(&mut self) -> Result<DisplayInfo, WindowError> {
        self.display.query()
    }
    fn CreateSurface(&mut self, _: &CStr, size: Size) -> Result<SurfaceHandle, WindowError> {
        if !size.IsValid() {
            return Err(WindowError::InvalidSize);
        }
        let id = self.next;
        self.next += 1;
        self.handles.insert(id, Box::new(id as u64));
        Ok(SurfaceHandle(id))
    }
    fn SetLayer(&mut self, _: &SurfaceHandle, _: i32) -> Result<(), WindowError> {
        Ok(())
    }
    fn SetTrustedOverlay(&mut self, _: &SurfaceHandle, _: bool) -> Result<(), WindowError> {
        Ok(())
    }
    fn SetSkipScreenshot(&mut self, _: &SurfaceHandle, enabled: bool) -> Result<(), WindowError> {
        self.filter(enabled)
    }
    fn SetBufferSize(&mut self, _: &SurfaceHandle, size: Size) -> Result<(), WindowError> {
        if size.IsValid() {
            Ok(())
        } else {
            Err(WindowError::InvalidSize)
        }
    }
    fn AcquireNativeWindow(
        &mut self,
        s: &SurfaceHandle,
    ) -> Result<NonNull<ANativeWindow>, WindowError> {
        // Opaque token passed only to SkiaBackend; never dereferenced as ANativeWindow.
        self.handles
            .get_mut(&s.0)
            .map(|b| NonNull::from(b.as_mut()).cast())
            .ok_or(WindowError::Stopped)
    }
    fn ProcessMirrorDisplay(&mut self) -> Result<(), WindowError> {
        Ok(())
    }
    fn DestroySurface(&mut self, s: SurfaceHandle) {
        self.handles.remove(&s.0);
    }
}
