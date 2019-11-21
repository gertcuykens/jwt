export let origin = ""

const get = (url) => fetch(origin + url, {
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
  .then(obj => console.log(obj === null))

export const logout = () => get('/logout')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

export const originc = () => get('/origin')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

// document.cookie = 'Authorization=; Max-Age=-1;';

// headers: {
//   'Content-Type': 'application/json'
// },
// body: JSON.stringify(obj),

// console.log(response.headers.get('Authorization'))

// get("/origin").then(origin => {
//   if (location.origin != origin) {
//     location.replace(origin)
//   }
// })

// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
// await sleep(2000)

// const empty = (obj) => Object.entries(obj).length === 0 && obj.constructor === Object
