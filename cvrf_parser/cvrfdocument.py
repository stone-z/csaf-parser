import json
import xmltodict
from attributedict.collections import AttributeDict


class CVRFDocument(AttributeDict):
    """
    (Schema Version)
    Document Title
    Document Type
    Document Publisher *
    Document Tracking *
    Document Notes *
    Document Distribution
    Aggregate Severity *
    Document References *
    Acknowledgements *

    Vulnerability **
    ProductTree **
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Capture and wrap ProductTree
        self.ProductTree = ProductTree(self.pop('ProductTree'))

        # Pre-process Vulnerabilities
        self.Vulnerabilities = []
        for v in self.pop('Vulnerability'):
            self.Vulnerabilities.append(Vulnerability(v))

        print("Notes: ", self.DocumentNotes)

    def __str__(self):
        return "{} {}: {}".format(self.DocumentType, self.DocumentTracking.Identification.ID, self.DocumentTitle)

    @classmethod
    def from_xml(cls, xml: str, lazy: bool = True):
        """
        Create a CVRFDocument from an existing XML file.
        :param xml: A file object from which to read the XML representation.
        :param lazy: If True (default) will delay parsing the document until elements are accessed.
        :return: A new CVRFDocument based on the given file.
        """
        # TODO: Might need streaming option for huge files

        with open(xml, 'rb') as f:
            doc_xml = xmltodict.parse(f, dict_constructor=dict, encoding='utf-8')
            # See if the root is cvrf-namespaced
            root_name = 'cvrfdoc' if 'cvrfdoc' in doc_xml.keys() else "cvrf:cvrfdoc"
            new_doc = cls(doc_xml[root_name])

        if not lazy:
            # Expand full tree
            # TODO: Not needed if using xmltodict without streaming?
            pass

        return new_doc

        # def is_valid(self) -> bool:
        #     """
        #     Checks whether a CVRFDocument generates a valid CVRF XML document.
        #     :return: True, if the resulting document conforms to the specified schema. Otherwise False.
        #     """
        #     pass


class ProductTree:  # AttributeDict
    """
    Branch * (recursive)
    Full Product Name *
    Relationship *
    Product Groups *
    """

    def __init__(self, source_dict: dict):
        # print("creating: ", source_dict)
        self.branch_list = None
        self.product_list = None

        if '@xmlns' in source_dict.keys():
            self.xmlns = source_dict.pop('@xmlns')

        # if '@Name' in source_dict.keys():
        #     self.Name = source_dict.pop('@Name')
        # if '@Type' in source_dict.keys():
        #     self.Type = source_dict.pop('@Type')
        # if '@FullProductName' in source_dict.keys():
        #     self.product_list = [Product(source_dict.pop('@FullProductName'))]
        self.root = ProductBranch(source_dict)
        # self.tree = AttributeDict(source_dict)

    # def __str__(self):
    #     return "Branch ({}) {}".format(self.Type, self.Name)

    def branches(self) -> tuple:
        # TODO: Return cached branch and product lists
        self.branch_list = self.branch_list if self.branch_list else self.root.branches()[0]
        return self.branch_list

    def products(self):
        self.product_list = self.product_list if self.product_list else self.root.branches()[1]
        return self.product_list

    def xbranches(self) -> list:
        # if hasattr(self, 'Name'):
        #     print(self.Name)
        if self.branch_list is None:
            branches = []
            self.branch_list = []
            if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
                # Either list or single dict
                if isinstance(self.tree.Branch, list):
                    for b in self.tree.Branch:
                        self.branch_list.extend(ProductTree(b).branches())
                elif isinstance(self.tree.Branch, dict):
                    # Single Branch nested in the current one
                    print("Dict: ", self.tree.Branch)
                    if hasattr(self.tree.Branch, 'Branch'):
                        # branches.extend(ProductTree(self.tree.Branch).branches())
                        self.branch_list.extend(ProductTree(self.tree.Branch).branches())
                        # print(len(self.branch_list))
                    else:
                        # This is a leaf node representing a single Product
                        # print("Single node: ", self.tree.Branch)
                        self.product_list = self.product_list or []
                        self.product_list.append(Product(**self.tree.Branch.FullProductName))
                        return [self]
            # self.branch_list = self.branch_list or []
            # self.branch_list.extend(branches)
        else:
            print(len(self.branch_list))
            # print(len(self.product_list))

        return self.branch_list

        # if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
        #     return json.dumps(self.tree.Branch, indent=4)
        # else:
        #     return ''

    def xproducts(self) -> list:
        # ProductTrees can have recursive branches, so I might be a branch or a leaf
        if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
            # Get all my child products
            branch_products = []
            print("My branch: ", json.dumps(self.tree.Branch, indent=4))
            # My Branch might be a single dict or a list
            if isinstance(self.tree.Branch, list):
                # For each of my listed Branches, get their Products
                for b in self.tree.Branch:
                    branch_products.extend(ProductTree(b).products())
            else:
                # Get the Products in my nested Branch
                for b in self.tree.Branch.Branch:
                    branch_products.extend(ProductTree(b).products())
            return branch_products

        else:
            # I have no children, so return myself as a list of a single Product
            return [Product(self.tree.FullProductName['@ProductID'],
                            self.tree.FullProductName['#text'],
                            self.tree.FullProductName.get('CPE', None))]


class ProductBranch(AttributeDict):
    def __init__(self, node, *args, **kwargs):
        # print("creating: ", kwargs)
        self.branch_list = []
        self.product_list = []

        if '@Name' in node.keys():
            self.Name = node.pop('@Name')
        if '@Type' in node.keys():
            self.Type = node.pop('@Type')
        # if '@FullProductName' in source_dict.keys():
        #     self.product_list = [Product(source_dict.pop('@FullProductName'))]
        super().__init__(node)

    def branches(self) -> tuple:
        print("Getting branches for ", (self.Name if hasattr(self, 'Name') else 'None'))
        if hasattr(self, 'Branch'):
            # I am not a Product leaf, so capture the branches and products under me
            sub_branch = self.Branch
            if isinstance(sub_branch, list):
                # I have a list of sub-Branches. Collect each one
                for b in sub_branch:
                    sub_branches, sub_products = ProductBranch(b).branches()
                    self.branch_list.extend(sub_branches)
                    self.product_list.extend(sub_products)
            else:
                # I have only one branch under my level
                # sub_branches, sub_products = ProductBranch(**sub_branch).branches()
                sub_branches, sub_products = ProductBranch(sub_branch).branches()
                self.branch_list.extend(sub_branches)
                self.product_list.extend(sub_products)

        else:
            # Base case -- no Branch under my level, so construct my branch and products
            # print(self.items())
            self.product_list.append(Product(**self.FullProductName))

        self.branch_list.append(self)

        # Pass my branches and products up to my caller
        return self.branch_list, self.product_list


class Product(AttributeDict):
    node_fields = {'@ProductID': 'ProductID', '@CPE': 'CPE',
                   'FullProductName': 'FullProductName', '#text': 'text'}

    def __init__(self, *args, **kwargs):
        # print("Creating: ", kwargs)

        for field in self.node_fields.keys():
            if field in kwargs.keys():
                setattr(self, self.node_fields[field], kwargs.pop(field))
        super().__init__(*args, **kwargs)

    def __str__(self):
        return "({}) {}".format(self.ProductID, self.text)


class xProduct:
    def __init__(self, pid, name, cpe=None):
        self.ProductID = pid
        self.FullProductName = name
        self.CPE = cpe

    def __str__(self):
        return "({}) {}".format(self.ProductID, self.FullProductName)


class Vulnerability(AttributeDict):
    """
    Ordinal
    Title
    ID *
    Notes *
    Discovery Date
    Release Date
    Involvements *
    CVE
    CWE *
    Product Statuses *
    Threats *
    CVSS Score Sets *
    Remediations *
    References *
    Acknowledgements *
    """

    # def __init__(self, *args, **kwargs):
    #     if '@Ordinal' in kwargs:
    #         self.Ordinal = kwargs.pop('@Ordinal')
    #     super().__init__(*args, **kwargs)

    def __str__(self):
        title = " {}".format(self.Title or ' Untitled')
        cve = " ({})".format(self.CVE or ' No CVE')
        return "{}:{}{}".format(self['@Ordinal'], cve, title)

    def threats(self) -> list:
        if hasattr(self, 'Threats'):
            threat_subkey = self.Threats.pop('Threat')
            threat_list = []

            if isinstance(threat_subkey, list):
                # Multiple threats in this vuln -- add them all
                for t in threat_subkey:
                    threat_list.append(Threat(**t))
            elif threat_subkey is not None:
                # Only one threat -- add it directly
                threat_list.append(Threat(**threat_subkey))
            return threat_list
        else:
            return []


class Threat(AttributeDict):
    def __init__(self, *args, **kwargs):
        if '@Type' in kwargs:
            self.threat_type = kwargs.pop('@Type')
        if 'Description' in kwargs:
            self.Description = kwargs.pop('Description')
        super().__init__(*args, **kwargs)

    def __str__(self):
        return "({}) {}".format(self.threat_type, self.Description)
