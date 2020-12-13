import nodePolyfills from 'rollup-plugin-node-polyfills';
import commonjs from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import { babel } from '@rollup/plugin-babel';
import json from '@rollup/plugin-json';
import { terser } from "rollup-plugin-terser";
import builtins from 'rollup-plugin-node-builtins';

export default {
    input: 'src/index.js',
    output: {
        dir: 'output',
        format: 'iife',
    },
    //browser: true,
    plugins: [
        nodeResolve(
        {
            preferBuiltins: false,
            browser: true
        }),
        commonjs(),
        nodePolyfills(),
        babel(),
        json(),
        builtins(),
        terser()
    ],
};
