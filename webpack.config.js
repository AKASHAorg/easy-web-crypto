const path = require('path')

module.exports = {
  entry: './src/index.js',
  target: 'web',
  devtool: 'source-map',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'web-crypto.js',
    library: 'WebCrypto',
    libraryTarget: 'umd',
    umdNamedDefine: true
  },
  node: {
    fs: 'empty'
  }
}
