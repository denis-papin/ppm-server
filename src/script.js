
function get_content() {
    alert("Here I am");
    fetch("/keyserver/key?token_id=b69Rd6VGEac7PpHd3J-e-g")
        .then(r => console.log(r));

}

