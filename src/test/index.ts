import UmapiCrypt from '../index'

const keys = UmapiCrypt.getKeys()
console.log(keys)
const code = UmapiCrypt.encode(keys.publik_key,'Мама мыла раму')
console.log(code);
const decode = UmapiCrypt.decode(keys.private_key, code.message)
console.log(decode)