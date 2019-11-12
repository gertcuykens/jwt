function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export const test = async () => {
  await sign({
    name: 'test',
    method: 'GET',
    path: '/test',
  })
    .catch(err => console.error(err))
    .then(obj => console.log(obj))

  await sleep(2000)

  await verify({
    name: 'test',
    method: 'GET',
    path: '/test',
  })
    .catch(err => console.error(err))
    .then(obj => console.log(obj))
}

const sign = async (obj) => {
  const response = await fetch('/sign', {
    method: 'POST',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(obj)
  })
  console.log(response.headers.get('Authorization'))
  return response.json()
}

const verify = async (obj, token) => {
  const response = await fetch('/verify', {
    method: 'POST',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token,
    },
    body: JSON.stringify(obj)
  })
  console.log(response.headers.get('Authorization'))
  return response.json()
}

test()
