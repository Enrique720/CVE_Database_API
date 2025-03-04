document.addEventListener('DOMContentLoaded', function() {
    let currentPage = 1;
    let perPage = 10;
    let sortBy = 'cve.published';
    let sortOrder = 'asc';

    const perPageSelect = document.getElementById('per_page');
    const pageNumberSpan = document.getElementById('page-number');
    const prevPageButton = document.getElementById('prev-page');
    const nextPageButton = document.getElementById('next-page');
    const cveTableBody = document.getElementById('cve-table').getElementsByTagName('tbody')[0];
    const publishedHeader = document.getElementById('published-header');
    const lastModifiedHeader = document.getElementById('last-modified-header');
    const totalCount = document.getElementById('total-results');

    function formatDate(dateString) {
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        return new Date(dateString).toLocaleDateString(undefined, options);
    }

    function fetchCves(page, perPage, sortBy, sortOrder) {
        fetch(`/api/cves?page=${page}&per_page=${perPage}&sort_by=${sortBy}&sort_order=${sortOrder}`)
            .then(response => response.json())
            .then(data => {
                totalCves = data.total;
                totalCount.textContent = `Total Records: ${totalCves}`; 
                
                cveTableBody.innerHTML = '';
                data.cves.forEach(cve => {
                    const row = cveTableBody.insertRow();
                    const cveIdCell = row.insertCell(0);
                    cveIdCell.innerHTML = `<a href="/cves/${cve.cve.id}">${cve.cve.id}</a>`;
                    row.insertCell(1).textContent = cve.cve.sourceIdentifier;
                    row.insertCell(2).textContent = formatDate(cve.cve.published);
                    row.insertCell(3).textContent = formatDate(cve.cve.lastModified);
                    row.insertCell(4).textContent = cve.cve.vulnStatus;
                });
                updateSortIcons();
            })
            .catch(error => console.error('Error fetching CVE data:', error));
    }

    function sortTableByDate(sortByField) {
        sortBy = sortByField;
        sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
        fetchCves(currentPage, perPage, sortBy, sortOrder);
    }

    function updateSortIcons() {
        const publishedIcon = publishedHeader.querySelector('i');
        const lastModifiedIcon = lastModifiedHeader.querySelector('i');

        if (sortBy === 'cve.published') {
            publishedIcon.className = sortOrder === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
            lastModifiedIcon.className = 'fas fa-sort';
        } else if (sortBy === 'cve.lastModified') {
            lastModifiedIcon.className = sortOrder === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
            publishedIcon.className = 'fas fa-sort';
        }
    }

    perPageSelect.addEventListener('change', function() {
        perPage = parseInt(this.value);
        currentPage = 1;
        pageNumberSpan.textContent = currentPage;
        fetchCves(currentPage, perPage, sortBy, sortOrder);
    });

    prevPageButton.addEventListener('click', function() {
        if (currentPage > 1) {
            currentPage--;
            pageNumberSpan.textContent = currentPage;
            fetchCves(currentPage, perPage, sortBy, sortOrder);
        }
    });

    nextPageButton.addEventListener('click', function() {
        currentPage++;
        pageNumberSpan.textContent = currentPage;
        fetchCves(currentPage, perPage, sortBy, sortOrder);
    });

    publishedHeader.addEventListener('click', function() {
        sortTableByDate('cve.published');
    });

    lastModifiedHeader.addEventListener('click', function() {
        sortTableByDate('cve.lastModified');
    });

    fetchCves(currentPage, perPage, sortBy, sortOrder);
});