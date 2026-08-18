//! Minimal PE parser for entry-point / section offsets and section hashes.

#[derive(Debug, Clone)]
pub struct PeImage {
    pub entry_point_off: usize,
    pub sections: Vec<PeSection>,
}

#[derive(Debug, Clone)]
pub struct PeSection {
    pub raw_ptr: usize,
    pub raw_size: usize,
    pub virtual_addr: u32,
    pub virtual_size: u32,
}

impl PeImage {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
        if e_lfanew + 24 > data.len() {
            return None;
        }
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return None;
        }
        let coff = e_lfanew + 4;
        let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().ok()?) as usize;
        let size_opt = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
        let opt = coff + 20;
        if opt + 20 > data.len() {
            return None;
        }
        let magic = u16::from_le_bytes(data[opt..opt + 2].try_into().ok()?);
        if magic != 0x10b && magic != 0x20b {
            return None;
        }
        let ep_rva = u32::from_le_bytes(data[opt + 16..opt + 20].try_into().ok()?);
        let sec_off = opt + size_opt;
        let mut sections = Vec::with_capacity(num_sections.min(96));
        for i in 0..num_sections.min(96) {
            let off = sec_off + i * 40;
            if off + 40 > data.len() {
                break;
            }
            let virtual_size = u32::from_le_bytes(data[off + 8..off + 12].try_into().ok()?);
            let virtual_addr = u32::from_le_bytes(data[off + 12..off + 16].try_into().ok()?);
            let raw_size = u32::from_le_bytes(data[off + 16..off + 20].try_into().ok()?) as usize;
            let raw_ptr = u32::from_le_bytes(data[off + 20..off + 24].try_into().ok()?) as usize;
            sections.push(PeSection {
                raw_ptr,
                raw_size,
                virtual_addr,
                virtual_size,
            });
        }
        let mut entry_point_off = ep_rva as usize;
        for s in &sections {
            let va = s.virtual_addr;
            let vsz = s.virtual_size.max(s.raw_size as u32);
            if ep_rva >= va && ep_rva < va + vsz {
                entry_point_off = s.raw_ptr.saturating_add((ep_rva - va) as usize);
                break;
            }
        }
        Some(Self {
            entry_point_off,
            sections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny hand-rolled PE32 with one section.
    fn tiny_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80; // e_lfanew
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF: Machine i386, 1 section
        b[0x84..0x86].copy_from_slice(&0x14c_u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&0x60u16.to_le_bytes()); // SizeOfOptionalHeader
                                                               // Optional magic PE32
        b[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        // AddressOfEntryPoint RVA 0x1000
        b[0x98 + 16..0x98 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        // Section at 0x98+0x60 = 0xf8
        let sec = 0xf8;
        b[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        b[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // vsize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // va
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        b
    }

    #[test]
    fn parse_tiny_pe() {
        let pe = PeImage::parse(&tiny_pe()).unwrap();
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.entry_point_off, 0x200);
        assert_eq!(pe.sections[0].raw_ptr, 0x200);
    }

    #[test]
    fn reject_non_pe() {
        assert!(PeImage::parse(b"MZ not a pe").is_none());
        assert!(PeImage::parse(b"\x7fELF").is_none());
    }
}
