pub struct ContinuityChecker {
    pub is_running: bool,
    flags: [bool; 16]
}

impl ContinuityChecker {
    pub fn new() -> ContinuityChecker {
        ContinuityChecker { flags: [false; 16], is_running: false }
    }

    pub fn invalidate(&mut self) -> () {
        for i in 0..15 {
            self.flags[i] = false;
        }
    }

    pub fn set_valid(&mut self, cc: u16) -> () {
        self.flags[cc as usize] = true;
    }

    pub fn start_with(&mut self, cc: u16) -> () {
        let upper_bound = cc as usize;
        for i in 0..upper_bound {
            self.flags[i] = true;
        }
        self.is_running = true;
    }

    pub fn is_valid(&self) -> bool {
        self.flags.into_iter().all(|&flag| flag)
    }
}