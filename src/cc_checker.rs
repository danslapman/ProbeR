pub struct ContinuityChecker {
    pub flags: [bool; 16]
}

impl ContinuityChecker {
    pub fn new() -> ContinuityChecker {
        ContinuityChecker { flags: [false; 16] }
    }

    pub fn invalidate(&mut self) -> () {
        for i in 0..15 {
            self.flags[i] = false;
        }
    }

    pub fn set_valid(&mut self, cc: u16) -> () {
        self.flags[cc as usize] = true;
    }

    pub fn is_valid(&self) -> bool {
        self.flags.into_iter().all(|&flag| flag)
    }
}