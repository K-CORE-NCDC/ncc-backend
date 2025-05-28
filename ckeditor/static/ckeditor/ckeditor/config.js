/**
 * @license Copyright (c) 2003-2022, CKSource Holding sp. z o.o. All rights reserved.
 * For licensing, see https://ckeditor.com/legal/ckeditor-oss-license
 */

CKEDITOR.editorConfig = function( config ) {
	// Define changes to default configuration here. For example:
	// config.language = 'fr';
	// config.uiColor = '#AADC6E';
	// config.linkDefaultProtocol = 'http://127.0.0.1:8000/';
	// items: [["http:127.0.0.1:8000","http:127.0.0.1:8000"]]
	config.extraAllowedContent = 'video[*]{*};source[*]{*}';
};



// var waitCKEDITOR = setInterval(function() {
//     if (window.CKEDITOR) {
//        clearInterval(waitCKEDITOR);
//        CKEDITOR.on( 'dialogDefinition', function( ev ) {
//             // Take the dialog name and its definition from the event data.
//             var dialogName = ev.data.name;
//             var dialogDefinition = ev.data.definition;

//             // Check if the definition is from the dialog window you are interested in (the 'Link' dialog window).
//             if ( dialogName == 'link' ) {
//                 // Get a reference to the 'Link Info' tab.
//                 var infoTab = dialogDefinition.getContents( 'info' );

//                 // Set the default value for the URL field.
//                 var urlField = infoTab.get( 'url' );
//                 urlField[ 'default' ] = 'www.example.com';
//             }
//         });
//     }
// }, 1000);

// CKEDITOR.on('dialogDefinition', (ev) => {
//     if (ev.data.name == 'link') {
//       ev.data.definition.getContents('target').get('linkTargetType')['default']='_blank';
//       ev.data.definition.getContents('info').get('protocol')['default']='https://{{request.get_host}}'
//     }
// });