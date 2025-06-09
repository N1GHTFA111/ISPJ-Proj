// financeTables.js

// Sample data for demonstration purposes (rendered from Flask)
// Injected via Jinja template tags

// Initialize variables to keep track of sorting status
let currentSortingColumn = null;
let currentSortingOrder = null;

// Number of rows to display per page
const rowsPerPage = 5;


function displayTable(table, page, data) {
  const tableBody = document.querySelector(`#${table} tbody`);
  tableBody.innerHTML = '';

  const startIndex = (page - 1) * rowsPerPage;
  const endIndex = startIndex + rowsPerPage;
  const tableData = data.slice(startIndex, endIndex);
  const properties = getThClasses(table);

  // Check if the table is currently sorted and get the sorting column and order
  const isSorted = currentSortingColumn && currentSortingOrder;
  const sortedColumn = currentSortingColumn;
  const sortOrder = currentSortingOrder;

  if (tableData.length === 0) {
    const row = document.createElement('tr');
    const noRecordsCell = document.createElement('td');
    noRecordsCell.textContent = 'No records found.';
    noRecordsCell.setAttribute('colspan', properties.length);
    row.appendChild(noRecordsCell);
    tableBody.appendChild(row);
  } else {
    tableData.forEach(item => {
      const row = document.createElement('tr');
      let rowcontent = '';

      for (const property of properties) {
        rowcontent += `<td>${item[property] ? item[property] : '-'}</td>`;
      }

      row.innerHTML = rowcontent;
      tableBody.appendChild(row);
    });

    // If the table is sorted, update the sorting button visibility
    if (isSorted) {
      const sortButtons = document.querySelectorAll(`#${table} .sort-btn`);
      sortButtons.forEach(button => {
        const column = button.getAttribute('data-column');
        const order = button.getAttribute('data-order');
        if (column === sortedColumn) {
          // Show the button and set the correct icon based on the current sorting order
          button.style.display = 'inline';
          button.innerHTML = order === 'asc' ? '&#9650;' : '&#9660;';
        } else {
          // Hide the button for non-sorted columns
          button.style.display = 'none';
        }
      });
    }
  }
}

function getThClasses(table) {
  const thElements = document.querySelectorAll(`#${table} th`);
  const classesArray = Array.from(thElements).map(th => th.classList.toString());
  return classesArray;
}

function displayPagination(table, data) {
  const totalRows = data.length;
  const totalPages = Math.ceil(totalRows / rowsPerPage);
  const pagination = document.getElementById(`${table}-pagination`);
  pagination.innerHTML = '';

  for (let i = 1; i <= totalPages; i++) {
    const liClass = i === 1 ? 'page-item active' : 'page-item';
    const linkClass = 'page-link';
    const listItem = document.createElement('li');
    listItem.className = liClass;
    const link = document.createElement('a');
    link.className = linkClass;
    link.href = '#';
    link.textContent = i;
    listItem.appendChild(link);
    pagination.appendChild(listItem);

    listItem.addEventListener('click', function(event) {
      event.preventDefault();
      displayTable(table, i, data);
      const activeItem = pagination.querySelector('.active');
      activeItem.classList.remove('active');
      listItem.classList.add('active');
    });
  }
}

function sortTableData(table, originalData, filteredData, column, sortOrder) {
  let data;
//  console.log('sortTableData sortOrder:', sortOrder)
  if (filteredData && filteredData.length > 0) {
    data = filteredData;
  } else {
    data = originalData;
  }

//  console.log('filteredData:', filteredData)
//  console.log('originalDate:', originalData)
//  console.log('data:', data)

  // Make sure data is an array
  if (!Array.isArray(data)) {
    console.error('Data is not an array.');
    return;
  }

  // Sort the data based on the selected column and sortOrder
  data.sort((a, b) => {
    const aValue = a[column];
    const bValue = b[column];

    if (aValue === bValue) return 0;

    if (sortOrder === 'asc') {
      return aValue < bValue ? -1 : 1;
    } else {
      return aValue > bValue ? -1 : 1;
    }
  });

  // Re-display the sorted table with the current pagination
  const currentPage = document.querySelector(`#${table}-pagination .active`).textContent;
  displayTable(table, parseInt(currentPage), data);
}

function removeSortingEventListeners(table) {
  const sortButtons = document.querySelectorAll(`#${table} .sort-btn`);
  sortButtons.forEach(button => {
    const clonedButton = button.cloneNode(true);
    button.parentNode.replaceChild(clonedButton, button);
  });
}

function sortButtonHandler(table, originalData, filteredData) {
  return function () {
    const propertyName = this.getAttribute('data-column');
    let sortOrder = this.getAttribute('data-order');

    if (!sortOrder) {
      sortOrder = 'asc';
    } else if (sortOrder === 'asc') {
      sortOrder = 'desc';
    } else {
      sortOrder = 'asc';
    }

    this.setAttribute('data-order', sortOrder);

    // Reset arrows for all buttons
    const sortButtons = document.querySelectorAll(`#${table} .sort-btn`);
    sortButtons.forEach(btn => {
      btn.innerHTML = '&#x21C5;';
    });

    // Set arrow for the clicked button based on the sort order
    this.innerHTML = sortOrder === 'asc' ? '&#x2191;' : '&#x2193;';

    // If there is filtered data, use it for sorting; otherwise, use the original data
    const data = filteredData && filteredData.length > 0 ? filteredData : originalData;
    sortTableData(table, originalData, data, propertyName, sortOrder);
  };
}

// Function to add click event listeners to table headers for sorting
function addSortingEventListeners(table, originalData, filteredData) {
  removeSortingEventListeners(table);

  const sortButtons = document.querySelectorAll(`#${table} .sort-btn`);
  sortButtons.forEach(button => {
    button.addEventListener('click', sortButtonHandler(table, originalData, filteredData));
  });
}

function convertToStandardDateFormat(timeString) {
  const date = new Date(timeString);
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function handleDateFilter(table) {
  const startDateInput = document.getElementById(`${table}-start-date`);
  const endDateInput = document.getElementById(`${table}-end-date`);

  let startDate = startDateInput.value;
  let endDate = endDateInput.value;

  // Check if the start date is greater than the end date, and swap them if needed
  if (startDate > endDate) {
    [startDate, endDate] = [endDate, endDate];
    startDateInput.value = startDate;
    endDateInput.value = endDate;
  }

  // Assuming you have separate data arrays for each table
  let tableData;
  switch (table) {
    case 'pointsTable':
      tableData = codes;
      break;
    case 'redeemedVouchersTable':
      tableData = voucherRedemptions;
      break;
    case 'transactionsTable':
      tableData = transactions;
      break;
    default:
      tableData = [];
      break;
  }

  const filteredData = tableData.filter(item => {
    const date = convertToStandardDateFormat(item.time);
    return date >= startDate && date <= endDate;
  });

  displayTable(table, 1, filteredData);
  displayPagination(table, filteredData);

  // Add sorting event listeners for the filtered data
  addSortingEventListeners(table, tableData, filteredData);
}

// Function to update the minimum value of the start date input based on the end date
function updateStartDateRange(startDateInput, endDateInput) {
  const endDateValue = endDateInput.value;
  const startDateValue = startDateInput.value;
  startDateInput.max = endDateValue;
  endDateInput.min = startDateValue

  if (startDateInput.value > endDateValue) {
    startDateInput.value = endDateValue;
  }

  if (endDateInput.value < startDateValue) {
    endDateInput.value = startDateValue;
  }
}

// Function to add event listener to the end date input
function addDateEventListener(table) {
  const startDateInput = document.getElementById(`${table}-start-date`);
  const endDateInput = document.getElementById(`${table}-end-date`);

  // Set initial start date range based on the initial end date
  updateStartDateRange(startDateInput, endDateInput);

  // Add event listener to update the start date range whenever the end date changes
  endDateInput.addEventListener('change', function () {
    updateStartDateRange(startDateInput, endDateInput);
  });

  startDateInput.addEventListener('change', function () {
    updateStartDateRange(startDateInput, endDateInput);
  });
}




// Initial display on page load
document.addEventListener('DOMContentLoaded', function() {
  // Sample data (replace these with your actual data, injected via Jinja template tags)

  // Sample data (replace these with your actual data, injected via Jinja template tags)

  displayTable('pointsTable', 1, codes);
  displayPagination('pointsTable', codes);

  displayTable('redeemedVouchersTable', 1, voucherRedemptions);
  displayPagination('redeemedVouchersTable', voucherRedemptions);

  displayTable('transactionsTable', 1, transactions);
  displayPagination('transactionsTable', transactions);

  // Add sorting event listeners for each table
  addSortingEventListeners('pointsTable', codes, []);
  addSortingEventListeners('redeemedVouchersTable', voucherRedemptions, []);
  addSortingEventListeners('transactionsTable', transactions, []);

  // Add event listener to the dates input for each table
  addDateEventListener('pointsTable');
  addDateEventListener('redeemedVouchersTable');
  addDateEventListener('transactionsTable');

  // Add event listeners for the checkboxes to toggle the date filter on and off
  const pointsFilterCheckbox = document.getElementById('points-filter-checkbox');
//  console.log(pointsFilterCheckbox)
  const redeemedVouchersFilterCheckbox = document.getElementById('redeemed-vouchers-filter-checkbox');
  const transactionsFilterCheckbox = document.getElementById('transactions-filter-checkbox');

  pointsFilterCheckbox.addEventListener('change', function () {
//      console.log('filtered enabled')
    if (pointsFilterCheckbox.checked) {
      handleDateFilter('pointsTable');
    } else {
      displayTable('pointsTable', 1, codes);
      displayPagination('pointsTable', codes);
      addSortingEventListeners('pointsTable', codes, []);
    }
  });

  redeemedVouchersFilterCheckbox.addEventListener('change', function () {
    if (redeemedVouchersFilterCheckbox.checked) {
      handleDateFilter('redeemedVouchersTable');
    } else {
      displayTable('redeemedVouchersTable', 1, voucherRedemptions);
      displayPagination('redeemedVouchersTable', voucherRedemptions);
      addSortingEventListeners('redeemedVouchersTable', voucherRedemptions, []);
    }
  });

  transactionsFilterCheckbox.addEventListener('change', function () {
    if (transactionsFilterCheckbox.checked) {
      handleDateFilter('transactionsTable');
    } else {
      displayTable('transactionsTable', 1, transactions);
      displayPagination('transactionsTable', transactions);
      addSortingEventListeners('transactionsTable', transactions, []);
    }
  });
});
