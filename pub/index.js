function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export const test = async () => {
  try {
    const obj = await sign({
      name: 'test',
      method: 'GET',
      path: '/test',
    })
    console.log(obj)
  } catch (err) {
    console.error(err);
  }

  await sleep(2000)

  try {
    const obj = await verify({
      name: 'test',
      method: 'GET',
      path: '/test',
    })
    console.log(obj)
  } catch (err) {
    console.error(err);
  }
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
  return await response.json()
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
  return await response.json()
}

test()
