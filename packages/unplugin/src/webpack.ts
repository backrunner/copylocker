/** webpack adapter: `import copylocker from '@copylocker/unplugin/webpack'`. */

import { unplugin } from './plugin.js'

export const webpack = unplugin.webpack
export default unplugin.webpack
