const path = require('path')

module.exports = {
  entry: './src/web-crypto.ts',
  target: 'web',
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },  
  output: {
    path: path.resolve(__dirname, 'dist/cjs'),
    filename: 'web-crypto.js',
    library: 'WebCrypto',
    libraryTarget: 'umd',
    umdNamedDefine: true
  },
  resolve: {
    fallback: {
      fs: false
    }
  }
}
