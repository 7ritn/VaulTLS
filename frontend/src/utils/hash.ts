import { argon2id } from 'hash-wasm';

const SALT = 'VaulTLSVaulTLSVaulTLSVaulTLS';

export async function hashPassword(password: string): Promise<string> {
    return await argon2id({
        password,
        salt: SALT,
        parallelism: 4,
        iterations: 3,
        memorySize: 64 * 1024, // 64MB
        hashLength: 50,
        outputType: 'encoded' // Returns formatted string
    });
}