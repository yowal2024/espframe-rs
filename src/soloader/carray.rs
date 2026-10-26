#[derive(Debug, Default, Clone)]
pub struct CStringArray {
    items: Vec<String>,
}

impl CStringArray {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn exists(&self, value: &str) -> bool {
        self.items.iter().any(|item| item == value)
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        self.items.get(index).map(String::as_str)
    }

    pub fn add(&mut self, value: &str) -> bool {
        self.items.push(value.to_owned());
        true
    }

    pub fn remove(&mut self, value: &str) -> bool {
        if let Some(pos) = self.items.iter().position(|item| item == value) {
            self.items.remove(pos);
            true
        } else {
            false
        }
    }
}
