function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export const test = async () => {
  let token
  try {
    const obj = await client('/sign', '', {
      usr: '',
      pwd: ''
    })
    console.log(obj)
    token = obj.Authorization
  } catch (err) {
    console.error(err);
  }

  await sleep(2000)

  try {
    const obj = await client('/verify', token)
    console.log(obj)
  } catch (err) {
    console.error(err);
  }
}

const client = async (url, token, obj) => {
  const response = await fetch(url, {
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

// const obj = new FormData()
// formData.append("usr", usr)
// formData.append("pwd", pwd)
