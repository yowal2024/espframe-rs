//! Owned ImGui snapshots. Only Rust-owned data crosses into RenderEngine.
use crate::render::RenderError;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

#[derive(Debug)]
pub(super) struct Texture {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Vertex {
    pub pos: [f32; 2],
    pub uv: [f32; 2],
    pub color: u32,
}
#[derive(Debug)]
pub(super) struct Command {
    pub vertices: Vec<Vertex>,
    pub indices: Vec<u16>,
    pub texture: Arc<Texture>,
    pub clip: [f32; 4],
    pub linear: bool,
}
#[derive(Debug)]
pub(super) struct Frame {
    pub width: f32,
    pub height: f32,
    pub commands: Vec<Command>,
    pub produced: Instant,
}
fn invalid() -> RenderError {
    RenderError::Ui("invalid or unsupported Skia draw data".into())
}

pub(super) fn snapshot(
    data: &imgui::DrawData,
    textures: &BTreeMap<u32, Arc<Texture>>,
) -> Result<Frame, RenderError> {
    let size = data.display_size();
    let origin = data.display_pos();
    if size
        .iter()
        .any(|n| !n.is_finite() || *n <= 0. || *n > 32768.)
        || origin.iter().any(|n| !n.is_finite())
    {
        return Err(invalid());
    }
    let mut frame = Frame {
        width: size[0],
        height: size[1],
        commands: Vec::new(),
        produced: Instant::now(),
    };
    let mut linear = true;
    let mut total = 0usize;
    for list in data.draw_lists() {
        for cmd in list.commands() {
            use imgui::render::DrawCmd;
            match cmd {
                DrawCmd::Elements {
                    count,
                    cmd_params: p,
                } => {
                    if count == 0 {
                        continue;
                    }
                    total = total.checked_add(count).ok_or_else(invalid)?;
                    if count % 3 != 0 || total > 3_000_000 || frame.commands.len() >= 4096 {
                        return Err(invalid());
                    }
                    let end = p.idx_offset.checked_add(count).ok_or_else(invalid)?;
                    let indices = list
                        .idx_buffer()
                        .get(p.idx_offset..end)
                        .ok_or_else(invalid)?;
                    let min = indices
                        .iter()
                        .map(|&i| i as usize)
                        .min()
                        .ok_or_else(invalid)?;
                    let max = indices
                        .iter()
                        .map(|&i| i as usize)
                        .max()
                        .ok_or_else(invalid)?;
                    let vertex_start = p.vtx_offset.checked_add(min).ok_or_else(invalid)?;
                    let vertex_end = p.vtx_offset.checked_add(max + 1).ok_or_else(invalid)?;
                    let vertices = list
                        .vtx_buffer()
                        .get(vertex_start..vertex_end)
                        .ok_or_else(invalid)?;
                    let texture_id = u32::try_from(p.texture_id.id())
                        .map_err(|_| RenderError::InvalidTexture)?;
                    let texture = textures
                        .get(&texture_id)
                        .ok_or(RenderError::InvalidTexture)?
                        .clone();
                    if p.clip_rect.iter().any(|n| !n.is_finite()) {
                        return Err(invalid());
                    }
                    let clip = [
                        p.clip_rect[0] - origin[0],
                        p.clip_rect[1] - origin[1],
                        p.clip_rect[2] - origin[0],
                        p.clip_rect[3] - origin[1],
                    ];
                    if clip[0] >= clip[2] || clip[1] >= clip[3] {
                        continue;
                    }
                    let vertices = vertices
                        .iter()
                        .map(|v| {
                            if v.pos.iter().chain(v.uv.iter()).any(|n| !n.is_finite()) {
                                return Err(invalid());
                            }
                            Ok(Vertex {
                                pos: [v.pos[0] - origin[0], v.pos[1] - origin[1]],
                                uv: v.uv,
                                color: v.col,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let indices = indices
                        .iter()
                        .map(|&i| u16::try_from(i as usize - min).map_err(|_| invalid()))
                        .collect::<Result<Vec<_>, _>>()?;
                    frame.commands.push(Command {
                        vertices,
                        indices,
                        texture,
                        clip,
                        linear,
                    });
                }
                DrawCmd::ResetRenderState | DrawCmd::SetSamplerLinear => linear = true,
                DrawCmd::SetSamplerNearest => linear = false,
                _ => return Err(invalid()), // Raw callbacks cannot outlive this ImGui frame.
            }
        }
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imgui_snapshot_owns_textures_and_handles_clip_sampler_and_large_vertex_offsets() {
        let mut context = imgui::Context::create();
        context
            .set_ini_filename::<std::path::PathBuf>(None)
            .unwrap();
        context.io_mut().set_display_size([640., 480.]);
        context
            .io_mut()
            .set_backend_flags(imgui::BackendFlags::RENDERER_HAS_VTX_OFFSET);
        unsafe {
            super::super::sampler_callbacks(true);
        }
        let atlas = context.font_atlas();
        let legacy = atlas.try_claim_legacy_renderer().unwrap();
        legacy.build();
        let pixels = legacy.tex_data().unwrap();
        let font = Arc::new(Texture {
            width: pixels.width(),
            height: pixels.height(),
            pixels: match pixels.format() {
                imgui::TextureFormat::RGBA32 => pixels.pixels().unwrap().to_vec(),
                imgui::TextureFormat::Alpha8 => pixels
                    .pixels()
                    .unwrap()
                    .iter()
                    .flat_map(|a| [255, 255, 255, *a])
                    .collect(),
            },
        });
        drop(pixels);
        unsafe {
            legacy.set_texture_id(imgui::TextureId::new(1));
        }
        drop(legacy);
        let image = Arc::new(Texture {
            width: 1,
            height: 1,
            pixels: vec![255, 0, 0, 128],
        });
        let mut textures = BTreeMap::from([(1, font), (2, image.clone())]);
        let ui = context.frame();
        let list = ui.get_background_draw_list();
        list.add_text([20., 20.], [1., 1., 1., 1.], "Skia snapshot");
        for _ in 0..17_000 {
            list.add_rect([30., 30.], [32., 32.], [1., 0., 0., 1.])
                .filled(true)
                .build();
        }
        list.set_sampler_nearest();
        list.with_clip_rect([40., 50.], [100., 120.], || {
            list.add_image(
                imgui::TextureId::new(2),
                [40., 50.],
                [100., 120.],
                [0., 0.],
                [1., 1.],
                [1., 1., 1., 1.],
            );
        });
        drop(list);
        let rendered = context.render_legacy();
        let data = rendered.draw_data();
        assert!(data
            .draw_lists()
            .flat_map(|l| l.commands())
            .any(|c| matches!(c,
            imgui::render::DrawCmd::Elements {cmd_params, ..} if cmd_params.vtx_offset > 0)));
        let frame = snapshot(data, &textures).unwrap();
        textures.remove(&2);
        assert!(matches!(
            snapshot(data, &textures),
            Err(RenderError::InvalidTexture)
        ));
        drop(textures);
        drop(rendered);
        drop(context);
        assert_eq!([frame.width, frame.height], [640., 480.]);
        let command = frame
            .commands
            .iter()
            .find(|c| Arc::ptr_eq(&c.texture, &image))
            .unwrap();
        assert_eq!(command.clip, [40., 50., 100., 120.]);
        assert!(!command.linear);
        assert_eq!(command.texture.pixels, [255, 0, 0, 128]);
        assert!(command
            .vertices
            .iter()
            .all(|v| v.pos[0] >= 40. && v.pos[1] >= 50.));
        assert!(frame
            .commands
            .iter()
            .all(|c| c.indices.iter().all(|i| (*i as usize) < c.vertices.len())));
    }
}
