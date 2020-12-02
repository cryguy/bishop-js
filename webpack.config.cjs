const path = require('path')

// noinspection WebpackConfigHighlighting
module.exports = {
    mode: 'production',
    entry: './src/index.js',
    output: {
        path: path.resolve('dist'),
        filename: '[name].bundle.js',
        library: 'bishop-js',
        libraryTarget: 'commonjs2'
    },
    optimization: {
        splitChunks: {
            chunks: 'all',
        },
    },
    module: {
        rules: [
            {
                test: /\.js?$/,
                exclude: /(node_modules)/,
                use: 'babel-loader'
            }
        ]
    },

    resolve: {
        fallback:{
            "crypto": require.resolve("crypto-browserify"),
            "buffer": require.resolve("buffer"),
            "stream": require.resolve("stream-browserify")
        },
        extensions: ['.js']
    }
}