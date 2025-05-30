const webfont = require('webfont').default;
const fs = require('fs');
const path = require('path');

const webfontConfig = {
  files: 'src/font/icons/*.svg',
  dest: 'src/font/',
  formats: ['ttf', 'eot', 'woff', 'woff2'],
  fontName: 'summernote',
  template: 'src/font/template.scss',
  destTemplate: 'src/styles/summernote/font.scss',
  templateFontName: 'summernote',
  templateClassName: 'note-icon',
  templateFontPath: './font/',
  fixedWidth: false,
  normalize: true,
};


webfont(webfontConfig).then(result => {
  Object.keys(result).map(type => {
    if (
      type === 'config' ||
      type === 'usedBuildInTemplate' ||
      type === 'glyphsData'
    ) {
      return;
    }

    const content = result[type];
    let file = null;

    if (type !== 'template') {
      file = path.resolve(path.join(webfontConfig['dest'], webfontConfig['fontName'] + '.' + type));
    } else {
      file = path.resolve(webfontConfig['destTemplate']);
    }
   

    fs.writeFileSync(file, content);
  });
}).catch(error => {
  throw error;
});
