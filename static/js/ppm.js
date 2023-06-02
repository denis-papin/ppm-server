function login() {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    var data = {
        user: username,
        password: password
    };

    fetch(`/ppm/login`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
        .then(
            response => response.json()
        )
        .then(
            data => {
                // console.log(data);
                localStorage.setItem('TOKEN', data.token);
                // Rediriger vers la page "search_page"
                window.location.href = '/ppm/search_page';
            })
        .catch(error => {
            console.error('Une erreur s\'est produite:', error);
        });

}

function navigateInputPage(uuid) {
    localStorage.setItem("SELECTED_ENTRY", uuid);
    window.location.href = '/ppm/input_page';
}

function performSearch(event) {
    event.preventDefault();
    const searchInput = document.getElementById('chars');
    const searchText = searchInput.value;

    // Récupérer la valeur du stockage local
    var global_token = localStorage.getItem('TOKEN');

    fetch(`/ppm/search?chars=${encodeURIComponent(searchText)}`, {
        headers: {
            'Content-Type': 'application/json',
            'token_id': global_token
        }
    })
        .then(response => response.json())
        .then(data => {
            // Traitement des résultats JSON
            console.log(data);
            drawResult(data);
        })
        .catch(error => {
            console.error('Une erreur s\'est produite:', error);
        });
}

function createField(label, value) {
    const inputItem = document.createElement('div');
    inputItem.classList.add('result-value');

    const labelItem = document.createElement('label');
    labelItem.textContent = label + ': ';
    inputItem.appendChild(labelItem);

    const inputField = document.createElement('input');
    inputField.setAttribute('readonly', true);
    inputField.value = value;
    inputItem.appendChild(inputField);

    return inputItem;
}

function drawResult(results) {
    const resultsContainer = document.getElementById('results-container');
    resultsContainer.classList.add('results-grid');
    resultsContainer.innerHTML = '';
    results.forEach(result => {
        var block = drawEntry(result);
        resultsContainer.appendChild(block);
    });
}

function drawEntry(result) {

    const block = document.createElement('div');
    block.classList.add('result-block');
    localStorage.setItem(result.uuid, JSON.stringify(result));
    block.appendChild(createField('UUID', result.uuid));
    block.appendChild(createField('Titre', result.title));
    block.appendChild(createField('Order', result.order));
    block.appendChild(createField('Nom', result.username));
    block.appendChild(createField('Pass', result.encrypted_pass));
    block.appendChild(createField('Site Web', result.url));
    block.appendChild(createField('Notes', result.notes));
    block.appendChild(createField('Date', result.timestamp));

    // Créer un élément bouton
    var button = document.createElement('button');
    button.textContent = 'Modifier';
    // Ajouter l'événement onclick
    const uuid = result.uuid;
    button.onclick = () => navigateInputPage(uuid);
    block.appendChild(button);
    return block;
}

async function decrypt(encrypted) {

    var global_token = localStorage.getItem('TOKEN');
    try {
        const response = await fetch(`/ppm/decrypt/${encodeURIComponent(encrypted)}`, {
            headers: {
                'Content-Type': 'application/json',
                'token_id': global_token
            }
        });
        if (!response.ok) {
            throw new Error('Erreur lors de la requête');
        }

        const data = await response.json();
        const clearText = data.clear_text;
        return clearText;

        // Faites ce que vous voulez avec clearText ici
    } catch (error) {
        console.error('Une erreur s\'est produite:', error);
    }

}

async function fillEntry() {
    console.log("start fill entry");
    var uuid = localStorage.getItem('SELECTED_ENTRY');
    if (uuid !== null && uuid !== "") {
        var data = JSON.parse(localStorage.getItem(uuid));
        var clear = await decrypt(data.encrypted_pass);
        console.log(clear);
        document.getElementById('uuid').value = data.uuid;
        document.getElementById('title').value = data.title;
        document.getElementById('username').value = data.username;
        document.getElementById('password').value = clear;
        document.getElementById('url').value = data.url;
        document.getElementById('notes').value = data.notes;
        document.getElementById('category').value = "";

    }
    console.log(data);
}

function saveEntry() {
    var title = document.getElementById('title').value;
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    var url = document.getElementById('url').value;
    var notes = document.getElementById('notes').value;
    var category = document.getElementById('category').value;

    // Récupérer la valeur du stockage local
    var global_token = localStorage.getItem('TOKEN');

    var data = {
        "title": title,
        "username": username,
        "pass": password,
        "url": url,
        "notes": notes,
        "category": category
    };

    fetch(`/ppm/add_key`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'token_id': global_token
        },
        body: JSON.stringify(data)
    })
        .then(
            response => response.json()
        )
        .then(
            data => {
                console.log(data);
            })
        .catch(error => {
            console.error('Une erreur s\'est produite:', error);
        });
}

