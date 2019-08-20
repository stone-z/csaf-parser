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
            new_doc = cls(xmltodict.parse(f, dict_constructor=dict, encoding='utf-8')['cvrfdoc'])

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
        self.tree = AttributeDict(source_dict)

    def branches(self):
        if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
            return json.dumps(self.tree.Branch, indent=4)
        else:
            return ''

    def products(self) -> list:
        # ProductTrees can have recursive branches, so I might be a branch or a leaf
        if hasattr(self.tree, 'Branch') and self.tree.Branch is not None:
            # Get all my child products
            branch_products = []
            for b in self.tree.Branch.Branch:
                branch_products.extend(ProductTree(b).products())
            return branch_products

        else:
            # I have no children, so return myself as a list of a single Product
            return [Product(self.tree.FullProductName['@ProductID'],
                            self.tree.FullProductName['#text'],
                            self.tree.FullProductName.get('CPE', None))]


class Product:
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
            return None


class Threat(AttributeDict):
    def __init__(self, *args, **kwargs):
        if '@Type' in kwargs:
            self.threat_type = kwargs.pop('@Type')
        if 'Description' in kwargs:
            self.Description = kwargs.pop('Description')
        super().__init__(*args, **kwargs)

    def __str__(self):
        return "({}) {}".format(self.threat_type, self.Description)
