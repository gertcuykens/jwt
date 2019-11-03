export const test = async () => {
  try {
    const obj = await client('/sign', '', {
      usr: '',
      pwd: ''
    })
    console.log(obj)
  } catch (err) {
    console.error(err);
  }

  try {
    const obj = await client('/verify', 'eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvIiwiYXVkIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImh0dHBzOi8vand0LmlvIl0sImV4cCI6MTU3Mjc3ODgzNCwiaWF0IjoxNTcyNzc1MjM0fQ.gd7yZKzbYvXEanAQnHJzrB5AqPVPnrPtU3aBOiZHybdjHSZnjpLozaOz4GGitkQCKT9iozikMiR_pKX3kGUxDw')
    console.log(obj)
  } catch (err) {
    console.error(err);
  }
}

const client = async (url, jwt, obj) => {
  const response = await fetch(url, {
    method: 'POST',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + jwt,
    },
    body: JSON.stringify(obj)
  })
  console.log(response.headers.get('Authorization'))
  return await response.json()
}

test()
// import('./index.js').then(m => index = m)


// const obj = new FormData()
// formData.append("usr", usr)
// formData.append("pwd", pwd)
