use std::fmt;

const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
const UTF8_FLAG: u16 = 0x0800;
const VERSION_20: u16 = 20;

pub(super) struct ZipBuilder {
    output: Vec<u8>,
    entries: Vec<CentralEntry>,
}

struct CentralEntry {
    name: Vec<u8>,
    crc32: u32,
    size: u32,
    local_offset: u32,
}

impl ZipBuilder {
    pub(super) const fn new() -> Self {
        Self {
            output: Vec::new(),
            entries: Vec::new(),
        }
    }

    pub(super) fn add(&mut self, name: String, data: &[u8]) -> Result<(), ZipError> {
        if name.is_empty() || name.contains("..") || name.starts_with(['/', '\\']) {
            return Err(ZipError::UnsafeName);
        }
        let name = name.into_bytes();
        let name_length = u16::try_from(name.len()).map_err(|_| ZipError::TooLarge)?;
        let size = u32::try_from(data.len()).map_err(|_| ZipError::TooLarge)?;
        let local_offset = u32::try_from(self.output.len()).map_err(|_| ZipError::TooLarge)?;
        let crc32 = crc32fast::hash(data);

        write_u32(&mut self.output, LOCAL_FILE_HEADER_SIGNATURE);
        write_u16(&mut self.output, VERSION_20);
        write_u16(&mut self.output, UTF8_FLAG);
        write_u16(&mut self.output, 0);
        write_u16(&mut self.output, 0);
        write_u16(&mut self.output, 0);
        write_u32(&mut self.output, crc32);
        write_u32(&mut self.output, size);
        write_u32(&mut self.output, size);
        write_u16(&mut self.output, name_length);
        write_u16(&mut self.output, 0);
        self.output.extend_from_slice(&name);
        self.output.extend_from_slice(data);

        self.entries.push(CentralEntry {
            name,
            crc32,
            size,
            local_offset,
        });
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Vec<u8>, ZipError> {
        let central_offset = u32::try_from(self.output.len()).map_err(|_| ZipError::TooLarge)?;
        for entry in &self.entries {
            let name_length = u16::try_from(entry.name.len()).map_err(|_| ZipError::TooLarge)?;
            write_u32(&mut self.output, CENTRAL_DIRECTORY_SIGNATURE);
            write_u16(&mut self.output, VERSION_20);
            write_u16(&mut self.output, VERSION_20);
            write_u16(&mut self.output, UTF8_FLAG);
            write_u16(&mut self.output, 0);
            write_u16(&mut self.output, 0);
            write_u16(&mut self.output, 0);
            write_u32(&mut self.output, entry.crc32);
            write_u32(&mut self.output, entry.size);
            write_u32(&mut self.output, entry.size);
            write_u16(&mut self.output, name_length);
            write_u16(&mut self.output, 0);
            write_u16(&mut self.output, 0);
            write_u16(&mut self.output, 0);
            write_u16(&mut self.output, 0);
            write_u32(&mut self.output, 0);
            write_u32(&mut self.output, entry.local_offset);
            self.output.extend_from_slice(&entry.name);
        }
        let central_size = u32::try_from(self.output.len())
            .map_err(|_| ZipError::TooLarge)?
            .checked_sub(central_offset)
            .ok_or(ZipError::TooLarge)?;
        let count = u16::try_from(self.entries.len()).map_err(|_| ZipError::TooManyEntries)?;
        write_u32(&mut self.output, END_OF_CENTRAL_DIRECTORY_SIGNATURE);
        write_u16(&mut self.output, 0);
        write_u16(&mut self.output, 0);
        write_u16(&mut self.output, count);
        write_u16(&mut self.output, count);
        write_u32(&mut self.output, central_size);
        write_u32(&mut self.output, central_offset);
        write_u16(&mut self.output, 0);
        Ok(self.output)
    }
}

#[derive(Debug)]
pub(super) enum ZipError {
    TooLarge,
    TooManyEntries,
    UnsafeName,
}

impl fmt::Display for ZipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("ZIP exceeds the classic ZIP size limit"),
            Self::TooManyEntries => formatter.write_str("ZIP contains too many entries"),
            Self::UnsafeName => formatter.write_str("ZIP entry name is unsafe"),
        }
    }
}

impl std::error::Error for ZipError {}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_classic_zip_signatures() {
        let mut zip = ZipBuilder::new();
        zip.add("hello.txt".to_owned(), b"hello")
            .expect("entry should fit");
        let bytes = zip.finish().expect("ZIP should finish");
        assert_eq!(&bytes[..4], &LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        assert!(
            bytes
                .windows(4)
                .any(|window| window == END_OF_CENTRAL_DIRECTORY_SIGNATURE.to_le_bytes())
        );
    }
}
