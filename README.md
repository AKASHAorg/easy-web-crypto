# Secure-store

This is a secure, promise-based keyval store that encrypts data stored in IndexedDB.

The symmetric encryption key is derived from the provided passphrase, and then stored in an encrypted form within the provided store name. The encryption key is only used in memory and never revealed.

The IndexedDB wrapper used internally is [idb-keyval](https://github.com/jakearchibald/idb-keyval/).

## Usage

### Initialize

The init step takes care of key derivation and setting up the encryption/decription key.

```js
const Store = require('secure-store')

const store = new Store('some-store-name', 'super-secure-passphrase')

store.init().then(() => {
  // store is ready
})
```

### set:

```js
store.set('hello', 'world')
```

Since this is IDB-backed, you can store anything structured-clonable (numbers, arrays, objects, dates, blobs etc).

All methods return promises:

```js
store.set('hello', 'world')
  .then(() => console.log('It worked!'))
  .catch(err => console.log('It failed!', err))
```

### get:

```js
// logs: "world"
store.get('hello').then(val => console.log(val))
```

If there is no 'hello' key, then `val` will be `undefined`.

### keys:

```js
// logs: ["hello", "foo"]
keys().then(keys => console.log(keys))
```

### del:

```js
store.del('hello')
```

### clear:

```js
store.clear()
```

That's it!

## Installing

### Via npm

```sh
npm install git+https://github.com/deiu/secure-store#master
```

### Via `<script>`

* `dist/secure-store.js` can be directly used in browsers.
