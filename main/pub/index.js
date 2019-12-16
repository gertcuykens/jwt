const get = (url) => fetch(url, {
  method: 'GET',
  cache: 'no-cache',
  credentials: 'include',
}).then(response => response.json())

export const authorization = async (v) => {
  await get('/logout')
  document.cookie = 'Authorization=' + escape(v) + '; path=/'
  return get('/authorization')
    .catch(err => console.error(err))
    .then(obj => console.log(obj))
}

export const sign = () => get('/sign')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

export const verify = () => get('/verify')
  .catch(err => console.error(err))
  .then(obj => console.log(obj)) // === null

export const v25519 = () => get('/25519')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

export const logout = () => get('/logout')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

// document.cookie = 'Authorization=; Max-Age=-1;';
// console.log(response.headers.get('Authorization'))

// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
// await sleep(2000)

// const empty = (obj) => Object.entries(obj).length === 0 && obj.constructor === Object

// headers: {'Content-Type': 'application/json'},
// body: JSON.stringify(obj),
