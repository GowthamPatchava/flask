(function($){
  $(function(){

    $('.sidenav').sidenav();

    $('.slider').slider({fullwidth: true, indicators: false, height: 700, duration: 400, interval: 3000});
    $('.modal').modal({preventScrolling: false});
    $('.collapsible').collapsible();
    $('.scrollspy').scrollSpy();
    $('input#input_text, textarea#textarea2').characterCounter();

  }); // end of document ready
})(jQuery); // end of jQuery name space
