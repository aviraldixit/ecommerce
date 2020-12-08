$(document).ready(function() {
$('.my-form2').hide();

$("#defaultSwitch").change(function() {

        if ($('#defaultSwitch').prop("checked") == true) {
        console.log('Default Switch toggled')
        $('.my-form2').show();
        if ($('#anotherSwitch').prop("checked") == true) {
        $('#anotherSwitch').click();
        }
        $('.my-form1').hide();
        }
        });
$("#anotherSwitch").change(function() {
        if ($('#anotherSwitch').prop("checked") == true) {
        console.log('Another Switch toggled')
        $('.my-form1').show();
        if ($('#defaultSwitch').prop("checked") == true) {
        $('#defaultSwitch').click();
        }
        $('.my-form2').hide();
        }
        });


});