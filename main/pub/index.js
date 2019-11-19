const f = async (method, url) => {
  const response = await fetch(url, {
    method: method,
    cache: 'no-cache',
    // credentials: 'include',
    // headers: {
    //   'Content-Type': 'application/json',
    // },
  })
  return response.json()
}

// const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
// await sleep(2000)

export const subject = (v) => {
  document.cookie = 'Authorization=' + escape(v) + '; path=/'
  return f('POST', '/subject')
    .catch(err => console.error(err))
    .then(obj => console.log(obj))
}

export const sign = () => f('PUT', '/sign/test-path')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

export const verify = () => f('PUT', '/verify')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

export const rm = () => f('DELETE', '/delete')
  .catch(err => console.error(err))
  .then(obj => console.log(obj))

// console.log(response.headers.get('Authorization'))
// document.cookie = 'Authorization=; Max-Age=-1;';
