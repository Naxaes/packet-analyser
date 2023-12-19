pub fn be_to_fe<const C: usize>(mut bytes: [u8; C]) -> [u8; C] {
    let middle = C / 2;
    let (first, second) = bytes.split_at_mut(middle);
    for i in 0..middle {
        std::mem::swap(&mut first[i], &mut second[middle-i-1])
    };
    return bytes;
}
