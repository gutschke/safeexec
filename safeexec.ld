SECTIONS {
  .ephemeralBinary : {
    _start_ephemeralBinary = .;
    KEEP(*(.ephemeralBinary))
    KEEP(*(.ephemeralBinaryRO))
    _end_ephemeralBinary = .;
  }
} INSERT AFTER .text;
