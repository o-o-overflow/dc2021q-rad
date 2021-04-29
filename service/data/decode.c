extern unsigned long int entrypoint(unsigned char* buffer) {
    unsigned char output = 0;
    for (int i = 0; i < 8; i++) {
        int num_1 = 0;
        for (int j = 1; j < 8; j++) {
            if (buffer[j] & (1 << (7 - i))) {
                num_1 += 1;
            }
        }
        output <<= 1;
        if (num_1 >= 4) {
            output |= 1;
        }
    }
    return output;
}
