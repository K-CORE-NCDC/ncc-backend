$(document).ready(function(){

	focusIn = function(_obj){
		setTimeout(function(){
			$(_obj).focus();
		},500);
	};

	byteCalculation = function(bytes) {
        var bytes = parseInt(bytes);
        var s = ['bytes', 'kb', 'mb', 'gb', 'tb', 'pb'];
        var e = Math.floor(Math.log(bytes)/Math.log(1024));
        if(e == "-Infinity"){
        	return "0 "+s[0];
        }else{
        	return (bytes/Math.pow(1024, Math.floor(e))).toFixed(0)+" "+s[e];
        }
	};

	$(".download").on("click", function(){
    	var linkId	= $(this).parent().find("input[name=linkId]").val();
    	var fileSn	= $(this).parent().find("input[name=fileSn]").val();
		document.location = "/cmmn/file/download.do?linkId="+linkId+"&fileSn="+fileSn;
	});

	$(".logout").on("click", function(){
		document.location = "/sign/logout.do";
	});

	// ì—ë””í„°ì— ëŒ€í•œ ì´ë¯¸ì§€ ì´ë²¤íŠ¸
	$(document).on("change", "div.note-editor input[name=files]", function(){

		var obj = $(this);
		if($(this).val() != ""){

			var total = 0;
		    var formData = new FormData();
		    formData.append("files", $(this)[0].files[0]);

		    var ajaxReq = $.ajax({
				url : '/cmmn/file/image/upload.do',
				type : 'post',
				data : formData,
				cache : false,
				contentType : false,
				processData : false,
		    	complete: function(xhr, data) {
		    		var ajaxObj = eval(xhr.responseText);
		    		$("div.note-editor input[name=files]").val("");
		    		$("div.modal").modal("hide");
		    		var objName = $(obj).parent().parent().parent().parent().parent().parent().parent().find("textarea").attr("name");
		    		$("textarea[name="+objName+"]").summernote('insertImage', "/images/temp/editor/"+ajaxObj[0].pfile, ajaxObj[0].lfile);
		    	}
			});

			ajaxReq.fail(function(jqXHR) {
				//$('#alertMsg').text(jqXHR.responseText+'('+jqXHR.status+' - '+jqXHR.statusText+')');
				//$('button[type=submit]').prop('disabled',false);
			});
		}
	});

	/**
	 * ê³µí†µ : ì²¨ë¶€íŒŒì¼ ì—…ë¡œë“œ ì´ë²¤íŠ¸
	 */
	$("#fileupload").on("change", function(){
		var obj = $(this);
		if($(obj).val() != ""){
			var total = 0;
			var form;
			if($(obj).parent().find("input[name=frmName]").val() == ""){
				form = document.forms[0];
			}else{
				form = document.forms[$(obj).parent().find("input[name=frmName]").val()];
			}
		    var formData	= new FormData(form);
		    var inflowType	= $(obj).parent().find("input[name=inflowType]").val();
		    var uploadType	= $(obj).parent().find("input[name=uploadType]").val();
		    var fileType	= $(obj).parent().find("input[name=fileType]").val();
		    var fileSize	= $(obj).parent().find("input[name=fileSize]").val();
		    formData.append("inflowType", inflowType);
		    formData.append("uploadType", uploadType);

		    // íŒŒì¼ í™•ìž¥ìž ì²´í¬
		    var ext = $.trim($(obj).val()).split(".").pop().toLowerCase();
            if($.inArray(ext, fileType.split(",")) == -1){
				swalInit.fire("ì˜¤ë¥˜ ë°œìƒ","["+fileType+"] íŒŒì¼ë§Œ ì—…ë¡œë“œ í•´ì£¼ì„¸ìš”.","error");
                $(this).val("");
                return false;
            }

            // ìš©ëŸ‰ ì²´í¬
            var upFileSize = this.files[0].size;
            var maxSize = parseInt(fileSize);
            if(upFileSize > maxSize){
				swalInit.fire("ì˜¤ë¥˜ ë°œìƒ","íŒŒì¼ìš©ëŸ‰ "+fileSize+"ì„ ì´ˆê³¼í–ˆìŠµë‹ˆë‹¤.","error");
                $(this).val("");
                return false;
            }
		    var ajaxReq = $.ajax({
				url : '/cmmn/file/upload.do',
				type : 'post',
				data : formData,
				cache : false,
				contentType : false,
				processData : false,
				xhr: function(){
					//Get XmlHttpRequest object
					var xhr = $.ajaxSettings.xhr() ;
					//Set onprogress event handler
					xhr.upload.onprogress = function(event){

			        	var progress = parseInt(event.loaded / event.total * 100, 10);
			        	$("div.file-upload .progress").show();
			        	$("div.file-upload .progress").find(".progress-bar").css("width",progress+"%");


						//if(total == 0){
							/*
							if($("ul#file-upload-list li").hasClass("not-file")){
								$("ul#file-upload-list li").remove();
							}
				        	if($("ul#file-upload-list li").length == 0){
			            		$("ul#file-upload-list").show();
			            	}
							var html = "<li class='list-group-item d-flex justify-content-between align-items-center progress-bar'>ì—…ë¡œë“œ</li>";
			            	$("ul#file-upload-list").append(html);
			            	*/
						//}else{
				        	//var progress = parseInt(event.loaded / event.total * 100, 10);
				        	//$("div.file-upload .progress").show();
				            //$("div.file-upload .progress").css("width",progress+"%");
						//}
						//total++;
					};
					return xhr;
		    	},
		    	complete: function( xhr, data ) {

		    		var rtn = eval(xhr.responseText);

		    		$("div.file-upload .progress").hide();
		    		$("#file-upload-list").show();

		    		if(rtn.length > 0){

		    			for(var i=0;i<rtn.length;i++){
				    		var html = "";
				    		html += "<li class=\"list-group-item d-flex justify-content-between align-items-center px-2 py-2\">";
				    		html += "<input type=\"hidden\" name=\"arrFileSn\" value=\""+rtn[i].fileSn+"\">";
							html += "<span>"+rtn[i].lfile+"</span>";
				    		html += "	<a class=\"trash\" style=\"cursor:pointer\">";
							html += "		<i class=\"icon-bin trash text-danger\"></i>";
							html += "	</a>";
				    		html += "</li>";
				    		$("#file-upload-list").append(html);
		    			}
		    		}

		    	}
			});
		}
	});





	/**
	 * ê³µí†µ : ì²¨ë¶€íŒŒì¼ ì—…ë¡œë“œ ì‚­ì œ ì´ë²¤íŠ¸
	 */
	$(document).on("click", "#file-upload-list .trash", function(){
		var obj = $(this);
		swalInit.fire({
			title: "íŒŒì¼ì„ ì‚­ì œí•˜ì‹œê² ìŠµë‹ˆê¹Œ?",
			text: "",
			type: 'warning',
			showCancelButton: true,
			confirmButtonColor: '#3085d6',
			cancelButtonColor: '#d33',
			confirmButtonText: "ì‚­ì œ",
			cancelButtonText: "ì·¨ì†Œ"
		}).then(function(result){
			if (result.value) {
				if($(obj).parent().find("input[name=fileSn]").val() != undefined){
					$("div#file-delete-list").append("<input type=\"hidden\" name=\"arrDelFileSn\" value=\""+$(obj).parent().find("input[name=fileSn]").val()+"\" />");
				}
				$(obj).parent().remove();
				if($("#file-upload-list").find("li").length == 0){
					$("#file-upload-list").hide();
				}
			}
		});
	});

	$(document).on("click", "button[name=postSearch]", function(){
		new daum.Postcode({
            oncomplete: function(data) {
                // íŒì—…ì—ì„œ ê²€ìƒ‰ê²°ê³¼ í•­ëª©ì„ í´ë¦­í–ˆì„ë•Œ ì‹¤í–‰í•  ì½”ë“œë¥¼ ìž‘ì„±í•˜ëŠ” ë¶€ë¶„.

                // ë„ë¡œëª… ì£¼ì†Œì˜ ë…¸ì¶œ ê·œì¹™ì— ë”°ë¼ ì£¼ì†Œë¥¼ í‘œì‹œí•œë‹¤.
                // ë‚´ë ¤ì˜¤ëŠ” ë³€ìˆ˜ê°€ ê°’ì´ ì—†ëŠ” ê²½ìš°ì—” ê³µë°±('')ê°’ì„ ê°€ì§€ë¯€ë¡œ, ì´ë¥¼ ì°¸ê³ í•˜ì—¬ ë¶„ê¸° í•œë‹¤.
                var roadAddr = data.roadAddress; // ë„ë¡œëª… ì£¼ì†Œ ë³€ìˆ˜
                var extraRoadAddr = ''; // ì°¸ê³  í•­ëª© ë³€ìˆ˜

                // ë²•ì •ë™ëª…ì´ ìžˆì„ ê²½ìš° ì¶”ê°€í•œë‹¤. (ë²•ì •ë¦¬ëŠ” ì œì™¸)
                // ë²•ì •ë™ì˜ ê²½ìš° ë§ˆì§€ë§‰ ë¬¸ìžê°€ "ë™/ë¡œ/ê°€"ë¡œ ëë‚œë‹¤.
                if(data.bname !== '' && /[ë™|ë¡œ|ê°€]$/g.test(data.bname)){
                    extraRoadAddr += data.bname;
                }
                // ê±´ë¬¼ëª…ì´ ìžˆê³ , ê³µë™ì£¼íƒì¼ ê²½ìš° ì¶”ê°€í•œë‹¤.
                if(data.buildingName !== '' && data.apartment === 'Y'){
                   extraRoadAddr += (extraRoadAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                }
                // í‘œì‹œí•  ì°¸ê³ í•­ëª©ì´ ìžˆì„ ê²½ìš°, ê´„í˜¸ê¹Œì§€ ì¶”ê°€í•œ ìµœì¢… ë¬¸ìžì—´ì„ ë§Œë“ ë‹¤.
                if(extraRoadAddr !== ''){
                    extraRoadAddr = ' (' + extraRoadAddr + ')';
                }

                $("input[name=post]").val(data.zonecode);
                $("input[name=address]").val(roadAddr+extraRoadAddr);

            }
        }).open();
	});

	$(".modal button[name=close]").on("click", function(){
		$(".modal").modal("hide");
	});


	$("#onlineHelpEdit").on("click", function(){
		var tbl = $(this).attr("data-tbl");
		var code = $(this).attr("data-code");
		var mnId = $(this).attr("data-mnId");
		$(this).attr("href","/support/doc/upd.do?tbl="+tbl+"&code="+code+"&mnId=1028");
		$("#modal-online-help").modal("hide");
	});

	$(".online-help").on("click", function(){

		var tbl = $(this).attr("data-tbl");
		var code = $(this).attr("data-code");

		$.ajax({
            type : "post",
            url : "/support/doc/sel.do",
	        async : false,
	        dataType : "json",
	        data : {
				tbl : tbl	,
				code : code
	        },
            error : function(){
				swalInit.fire("ì˜¤ë¥˜ ë°œìƒ","ì„œë²„ ìš”ì²­ ë„ì¤‘ ì˜¤ë¥˜ê°€ ë°œìƒí–ˆìŠµë‹ˆë‹¤!!!","error");
            },
            success : function(_data){
    			$("#modal-online-help .modal-body").html(_data.detail);
    			$("#onlineHelpEdit").attr("data-tbl",	tbl);
    			$("#onlineHelpEdit").attr("data-code",	code);
            }
        });

		$("#modal-online-help").modal("show");
	});

//	$(document).on("submit", function(){
//		return false;
//	});

});
