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

export const logout = () => get('/logout')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))
