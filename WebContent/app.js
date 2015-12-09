$(document).ready(function() {

    //Stops the submit request
    $("#scanAjaxRequestForm").submit(function(e){
           e.preventDefault();
    });
      
    //checks for the button click event
    $("#submitButton").click(function(e){
          
            //Get the form data and serialize
            dataString = $("#scanAjaxRequestForm").serialize();
            var userHost = $("input#userHost").val(); 
            dataString = "userHost=" + userHost;
                
            //Make the AJAX request, expecting JSON response
            $.ajax({		
                type: "POST",
                url: "NmapServer",
                data: dataString,
                dataType: "json",
               
                //if received a response from the server
                success: function(data, textStatus, jqXHR) {
                    //print scan report
                     if(data.success){
                         $("#ajaxResponse").html("");
                         $("#ajaxResponse").append("<b>Host name:</b> " + data.result.hostName + "<br/>");
                         $("#ajaxResponse").append("<b>IP:</b> " + data.result.ip + "<br/>");
                         $("#ajaxResponse").append("<b>Timestamp:</b> " + data.result.timeStamp + "<br/>");
                         $("#ajaxResponse").append("<b>Open ports:</b> " + data.result.openPorts + "<br/>");
                         $("#ajaxResponse").append("<b>New ports opened after previous scan:</b> " + data.result.newPortsOpened + "<br/>");
                         $("#ajaxResponse").append("<b>New ports closed after previous scan:</b> " + data.result.newPortsClosed + "<br/>"); 
                         
                         for(var i=0; i<data.result.prevScanTimeStamps.length; i++)
                         {
                        	 $("#ajaxResponse").append("<br/>");
                        	 $("#ajaxResponse").append("<b>Previous Scan </b> " + (i+1) + "<br/>");
                        	 $("#ajaxResponse").append("<b>Timestamp:</b> " + data.result.prevScanTimeStamps[i] + "<br/>");
                        	 $("#ajaxResponse").append("<b>Open Ports:</b> " + data.result.prevScanOpenPorts[i] + "<br/>");
                         }
                         
                     } 
                     //display error message
                     else {
                         $("#ajaxResponse").html("<div><b>Error: Enter a valid Hostname/IP.</b></div>");
                     }
                },
               
                //If there was no response from the server
                error: function(jqXHR, textStatus, errorThrown){
                     console.log("Error: Server did not respond to the request." + textStatus);
                      $("#ajaxResponse").html(jqXHR.responseText);
                },
               
                //capture the request before it was sent to server
                beforeSend: function(jqXHR, settings){
                    //adding some Dummy data to the request
                    settings.data += "&dummyData=whatever";
                    //disable the button until we get the response
                    $('#submitButton').attr("disabled", true);
                },
               
                //after the response or error functions are done
                complete: function(jqXHR, textStatus){
                    //enable the button 
                    $('#submitButton').attr("disabled", false);
                }
     
            });        
    });

});