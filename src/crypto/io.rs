use crypto::cbox::{ZEROBYTES};

pub struct Plaintext {
    data: Vec<u8>,
    size: usize,
}

pub struct Ciphertext {
    data: Vec<u8>,
    size: usize,
}

macro_rules! zerovec {
    () => {
        vec![0 as u8; ZEROBYTES]
    };
}

impl Plaintext {
    
    pub fn new() -> Plaintext {
        Plaintext{ data: zerovec!(), size: 0}
    }
    
    pub fn with_capacity(capacity: usize) -> Plaintext {
        let mut p = Plaintext {
            data: zerovec!(),
            size: 0,
        };
        p.data.reserve(ZEROBYTES+capacity);
        p
    }

    // TODO
    //pub unsafe fn from_raw_parts(ptr: *mut u8, length: usize,
    //                             capacity: usize) -> Plaintext {
    //    Plaintext { data: zerovec!(), size: 0 }
    //}

    pub fn capacity(&self) -> usize {
        self.data.capacity() - ZEROBYTES
    }
    
    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    pub fn reserve_exact(&mut self, additional: usize) {
        self.data.reserve_exact(additional);
    }

    pub fn shrink_to_fit(&mut self) {
        self.data.shrink_to_fit();
    }

    // TODO
    //pub fn into_boxed_slice(&mut self) => Box<[u8]> {
    //
    //}

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len+ZEROBYTES);
    }

    pub fn swap_remove(&mut self, index: usize) -> u8 {
        self.data.swap_remove(index+ZEROBYTES)
    }

    pub fn insert(&mut self, index: usize, element: u8) {
        self.data.insert(index+ZEROBYTES, element);
    }

    pub fn remove(&mut self, index: usize) -> u8 {
        self.data.remove(index+ZEROBYTES)
    }

    // TODO
    //pub fn retain<F>(&mut self, mut f: F) where F: FnMut(&u8) -> bool {
    //}

    pub fn push(&mut self, value: u8) {
        self.data.push(value);
    }
    
    pub fn pop(&mut self) -> Option<u8> {
        match self.size {
            ZEROBYTES => None,
            _         => self.data.pop(),  
        }
    }

    pub fn clear(&mut self) {
        self.truncate(ZEROBYTES);
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == ZEROBYTES
    }
}
