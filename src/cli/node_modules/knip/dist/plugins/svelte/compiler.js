import { importsWithinScripts } from '../../compilers/compilers.js';
import { stylePreprocessorImports } from '../../compilers/style-preprocessors.js';
const compiler = (text, path) => {
    const scripts = importsWithinScripts(text, path);
    const styles = stylePreprocessorImports(text, path);
    if (!scripts)
        return styles;
    return styles ? `${scripts};\n${styles}` : scripts;
};
export default compiler;
