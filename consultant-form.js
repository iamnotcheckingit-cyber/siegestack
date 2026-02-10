// Define all skill categories
const skillCategories = {
    coreEngagements: [
        "Epicor Process Review",
        "Pre-EPR Review",
        "System Setup",
        "Process Development",
        "End User Training",
        "User Acceptance Testing/Conf Room Pilot",
        "PGLA - Pre Go Live Audit",
        "Go Live (Main)",
        "Go Live (Branch)",
        "Month End"
    ],
    specialtyEngagements: [
        "Avalara Tax Connect- Sales Tax",
        "B2B Admin Training",
        "Belting",
        "BillTrust",
        "Buying Trend Analysis",
        "Carrier Distributor functionality",
        "Worldpay - Credit Card",
        "CRM - Customer Relationship Management",
        "CSF - ANZ",
        "CSF - Canada",
        "CSF - Mexico",
        "CSF - UK",
        "DEA/Pedigree",
        "Document Imaging - Altec DocLink",
        "DynaChange Portal Designer",
        "EPX (Epicor Payment Exchange)",
        "HHBM - Hand Held Bin Management",
        "Language Packs",
        "Light Manufacturing",
        "Multiple Company Functionality",
        "P21 Mobile",
        "Parker Hannifin POS & Rebate Reporting",
        "Petro - Petroleum functionality",
        "POD - Proof of Delivery",
        "Progress Billing (part of Light Manf)",
        "Quickship (Functional Knowledge Only)",
        "Rentals",
        "Service & Maintenance",
        "Service Dispatch",
        "Service Pro (MSI)",
        "Shipping - UPSonline",
        "Slab/Stone Management",
        "TrackAbout",
        "USMCA",
        "Vendor Consignment",
        "VMI - Vendor Managed Inventory",
        "WWMS - Wireless Warehouse Management System"
    ],
    accountingSkills: [
        "AP Credit Card Processing",
        "AP Voucher Edit",
        "AR Invoice Edit",
        "Bank Reconciliation",
        "Cash Collections",
        "Cash Receipts",
        "Financial Statements",
        "GL Assignments & Transactional Postings",
        "Month End & Post Go Live - GL to AR/AP Reconciliation",
        "Pre-Pay Vouchers",
        "Receipt to Voucher Conversion",
        "Sales Tax",
        "Zip2Tax",
        "Year End Close",
        "1099 Functionality",
        "ACH Functionality",
        "AR Consolidated Invoices",
        "Customer Merge",
        "Deliquent AR Metrics",
        "Dimensional Accounting",
        "Statistical Accounts",
        "Landed Cost",
        "Multi-Company functionality",
        "Sales Tax by Zip Code",
        "Bank Reconciliation > Bank file import",
        "Landed Cost Tax Drivers/Canadian Taxes",
        "Merchandise Credits",
        "Multi-Currency functionality",
        "Vendor Invoice Automation"
    ],
    salesOrderSkills: [
        "Order, Quote Entry",
        "Freight & Freight Codes",
        "Front Counter Processing & Cash Drawers",
        "Front Counter Receipt Printing Options",
        "Quantity Restrictions",
        "Quick Order Entry",
        "Release Schedules",
        "Scheduler",
        "Shipping",
        "Adv Promise Date/Material Availability",
        "Cash Drawer - Scheduling Open/Close",
        "Customer Consignment",
        "Direct Through Stock (DTS)",
        "Job Control Functionality",
        "Lot Billing",
        "Manufacturer Rep Orders",
        "Retail Delivery Fee",
        "Tag & Hold",
        "Customer Rewards Program",
        "Intercompany Transfers",
        "Item Commitments",
        "Job Contract - Exporting & Importing",
        "Reallocation Processing",
        "Restricted Items & Dealer Types",
        "Room Functionality & Builders Allowance",
        "Scan and Pack"
    ],
    inventorySkills: [
        "ADF - Advanced Demand Forecasting",
        "PO Receipts & Receipt Reversal",
        "PORG - PO Req Generation window",
        "Purchasing/Replenishment Methods",
        "Safety Stock Analysis",
        "RFQ - Vendor Quotes",
        "Serial Number & Lot Tracking",
        "Lot Attributes",
        "DRP - Demand Requirements Planning",
        "Hazmat",
        "PORG - Automating PORG",
        "Revisions",
        "Scheduled POs",
        "Vessel/Container Tracking and Receipts",
        "Container Building",
        "Group Picking"
    ],
    productionSkills: [
        "Create Production Order from PORG",
        "Production Order Revision Level Tracking",
        "Production Orders",
        "Secondary Processing",
        "Update Prod Ord Assy from File",
        "Assembly Decoder & Hose Assemblies"
    ],
    pricingSkills: [
        "Contract Pricing",
        "Mass Updates",
        "Purchase Pricing setup, maintenance",
        "Sales Pricing setup, maintenance",
        "Commissions",
        "Margin of Last Sale",
        "Pricing Service",
        "AR Imports",
        "Imports/Exports",
        "Item Categories (Importing & Setting Up)",
        "Pricing Service Item Catalog Database",
        "Pricing Service TradeService Layout",
        "Scheduled Import Service Setup (SISS)",
        "Special Pricing Agreement (SPA)",
        "Vendor Contracts",
        "Vendor Rebates"
    ],
    warehouseSkills: [
        "Physical Count & Cycle Counting",
        "Transfers and Transfer Requirements Generation",
        "Labels",
        "Tagging",
        "Transfer Pallets",
        "Transfer Scheduling",
        "Warehouse Zones & Advanced Bin Mgt"
    ],
    crmSkills: [
        "Lost Sales Tracking",
        "Opportunity & Pipeline Mgt",
        "Call Center Task Generation",
        "Mail Merge",
        "Outlook/Exchange integration",
        "Telemarketing Call Mgt"
    ],
    extensibilitySkills: [
        "Business Workflow Alerts",
        "Report Studio",
        "Report Studio - Adding Tables",
        "DynaChange: Screen Designer",
        "DynaChange: Menu Designer",
        "DynaChange: Navigator",
        "DynaChange: Tab Designer",
        "New User Interface/Ribbon Metrics",
        "Widgets"
    ],
    functionalSkills: [
        "Accounting Expertise",
        "Sales Mgmt/Operations Expertise",
        "Building Materials",
        "Warehouse/Inventory Expertise",
        "Purchasing/Replenishment Expertise",
        "Production Operations Expertise",
        "Crystal/External Reporting",
        "Technical Expertise",
        "P21 Data Mapping Expertise",
        "Electrical Vertical Expertise",
        "Fastener Vertical Expertise",
        "Fluid Power Vertical Expertise",
        "HVAC Vertical Expertise",
        "Industrial Vertical Expertise",
        "DRP - Demand Requirements Planning",
        "Medical Vertical Expertise",
        "Paper & Packaging Vertical Expertise",
        "Petroleum Vertical Expertise",
        "Plumbing Vertical Expertise",
        "Tile/Slab Vertical Expertise",
        "Canadian Tax/Operations Expertise"
    ]
};

// Create skill dropdown
function createSkillSelect(name) {
    return `
        <select name="${name}">
            <option value="0">No Experience</option>
            <option value="1">Basic</option>
            <option value="2">Intermediate</option>
            <option value="3">Proficient</option>
            <option value="4">Expert</option>
        </select>
    `;
}

// Generate form fields for each category
function generateSkillFields(containerId, skills) {
    const container = document.getElementById(containerId);
    skills.forEach(skill => {
        const fieldName = skill.replace(/[^a-zA-Z0-9]/g, '_');
        const div = document.createElement('div');
        div.className = 'skill-item';
        div.innerHTML = `
            <span class="skill-label">${skill}</span>
            ${createSkillSelect(fieldName)}
        `;
        container.appendChild(div);
    });
}

// Initialize form
document.addEventListener('DOMContentLoaded', () => {
    generateSkillFields('coreEngagements', skillCategories.coreEngagements);
    generateSkillFields('specialtyEngagements', skillCategories.specialtyEngagements);
    generateSkillFields('accountingSkills', skillCategories.accountingSkills);
    generateSkillFields('salesOrderSkills', skillCategories.salesOrderSkills);
    generateSkillFields('inventorySkills', skillCategories.inventorySkills);
    generateSkillFields('productionSkills', skillCategories.productionSkills);
    generateSkillFields('pricingSkills', skillCategories.pricingSkills);
    generateSkillFields('warehouseSkills', skillCategories.warehouseSkills);
    generateSkillFields('crmSkills', skillCategories.crmSkills);
    generateSkillFields('extensibilitySkills', skillCategories.extensibilitySkills);
    generateSkillFields('functionalSkills', skillCategories.functionalSkills);
});

// Handle form submission
document.getElementById('expertiseForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData.entries());
    
    try {
        const response = await fetch('/.netlify/functions/submit-expertise', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            document.getElementById('successMessage').style.display = 'block';
            document.getElementById('errorMessage').style.display = 'none';
            e.target.reset();
            window.scrollTo(0, 0);
        } else {
            throw new Error('Submission failed');
        }
    } catch (error) {
        document.getElementById('errorMessage').style.display = 'block';
        document.getElementById('successMessage').style.display = 'none';
        window.scrollTo(0, 0);
    }
});
