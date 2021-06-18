import NodeRSA from 'node-rsa'

export interface RESPONSE {
    status: 'OK' | 'ERROR'
    message: string
    error?: Error
}

class UC {

    private secret: string | null = null

    private base64encode(str: string ): string  {
        return Buffer.from(str, 'utf8').toString('base64');
    }

    private base64decode(str: string): string {
        return Buffer.from(str, 'base64').toString('utf8');
    }

    getKeys(bytes: number = 1024 * 2 ): { private_key: string, publik_key: string } {
        const key = new NodeRSA({ b:bytes })
        const publik_key = this.base64encode(key.exportKey('public'))
        const private_key = this.base64encode(key.exportKey('private'))
        return { private_key, publik_key }
    }
    decode(private_key: string, code_str: string, secret: string|null = null ): RESPONSE {
        try {
            const key = new NodeRSA(this.base64decode(private_key))
            return { message: key.decrypt(code_str,'utf8'), status: 'OK' }
        } catch (error) {
            return {status: 'ERROR', message: error.message, error}
        }
    }
    encode(public_key: string, str: string, secret: string|null = null): RESPONSE{
        try {
            const key = new NodeRSA(this.base64decode(public_key))
            return { message: key.encrypt(str, 'base64'), status: 'OK'}
        } catch (error) {
            return {status: 'ERROR', message: error.message, error}
        }
    }
}

const UmapiCrypt: UC  = new UC()

export default UmapiCrypt
