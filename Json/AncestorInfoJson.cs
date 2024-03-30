using Newtonsoft.Json;
using System.Collections.Generic;

namespace AncestorInfoResource
{
    public class Ancestry
    {
        public string href;
    }

    public class Artifacts
    {
        public string href;
    }

    public class Attribution
    {
        public Contributor contributor;
        public object modified;
        public string changeMessage;
    }

    public class ChangeHistory
    {
        public string href;
    }

    public class Child
    {
        public string resource;
        public string resourceId;
        public string href;
    }

    public class Child3
    {
        public string resource;
        public string resourceId;
        public string href;
    }

    public class ChildAndParentsRelationship
    {
        public string id;
        public Parent1 parent1;
        public Parent2 parent2;
        public Child child;
        public Links links;
        public Identifiers identifiers;
        public List<Parent1Fact> parent1Facts;
        public List<Parent2Fact> parent2Facts;
        public List<Source> sources;
    }

    public class Citation
    {
        public string lang;
        public string value;
    }

    public class Collection
    {
        public string href;
    }

    public class ComponentOf
    {
        public string description;
    }

    public class Conclusion
    {
        public string href;
    }

    public class Contributor
    {
        public string resource;
        public string resourceId;
    }

    public class Date
    {
        public string original;
        public string formal;
        public List<Normalized> normalized;
    }

    public class Descendancy
    {
        public string href;
    }

    public class Description
    {
        public string href;
    }

    public class DiscussionReference
    {
        public string id;
        public string resource;
        public Attribution attribution;
        public string resourceId;
        public Links links;
    }

    public class DiscussionReference2
    {
        public string href;
    }

    public class Display
    {
        public string name;
        public string gender;
        public string lifespan;
        public string birthDate;
        public string birthPlace;
        public string deathDate;
        public string deathPlace;
        public string ascendancyNumber;
        public string descendancyNumber;
        public List<FamiliesAsParent> familiesAsParent;
        public List<FamiliesAsChild> familiesAsChild;
    }

    public class Evidence
    {
        public string id;
        public string resource;
        public string resourceId;
        public Attribution attribution;
        public Links links;
    }

    public class EvidenceReference
    {
        public string href;
    }

    public class Fact
    {
        public string id;
        public Attribution attribution;
        public string type;
        public Date date;
        public Place place;
        public Links links;
        public string value;
        public List<Qualifier> qualifiers;
    }

    public class Families
    {
        public string href;
    }

    public class FamiliesAsChild
    {
        public Parent1 parent1;
        public Parent2 parent2;
        public List<Child> children;
    }

    public class FamiliesAsParent
    {
        public Parent1 parent1;
        public Parent2 parent2;
        public List<Child> children;
    }

    public class Gender
    {
        public string id;
        public Attribution attribution;
        public string type;
        public Links links;
    }

    public class Identifiers
    {
        [JsonProperty("http://gedcomx.org/Persistent")]
        public List<string> httpgedcomxorgPersistent;

        [JsonProperty("http://familysearch.org/v1/ChildAndParentsRelationship")]
        public string httpfamilysearchorgv1ChildAndParentsRelationship;

        [JsonProperty("http://gedcomx.org/Primary")]
        public List<string> httpgedcomxorgPrimary;
    }

    public class Links
    {
        [JsonProperty("evidence-reference")]
        public EvidenceReference evidencereference;
        public Description description;
        public Parent1 parent1;
        public Relationship relationship;
        public Parent2 parent2;
        public Child child;

        [JsonProperty("source-reference")]
        public SourceReference sourcereference;
        public Conclusion conclusion;
        public Spouses spouses;

        [JsonProperty("change-history")]
        public ChangeHistory changehistory;
        public Ancestry ancestry;
        public Notes notes;

        [JsonProperty("non-matches")]
        public NonMatches nonmatches;
        public Portraits portraits;
        public Collection collection;
        public Families families;
        public Portrait portrait;
        public Matches matches;
        //public Children children ;
        public Descendancy descendancy;
        public Person person;

        [JsonProperty("source-descriptions")]
        public SourceDescriptions sourcedescriptions;
        public Merge merge;
        public Artifacts artifacts;
        public Parents parents;

        [JsonProperty("discussion-reference")]
        public DiscussionReference discussionreference;
        public Person2 person2;
        public Person1 person1;
    }

    public class Matches
    {
        public string href;
    }

    public class Merge
    {
        public string template;
        public string type;
        public string accept;
        public string allow;
        public string title;
    }

    public class Name
    {
        public string id;
        public Attribution attribution;
        public string type;
        public bool preferred;
        public Links links;
        public List<NameForm> nameForms;
        public string lang;
        public string value;
    }

    public class NameForm
    {
        public string lang;
        public string fullText;
        public List<Part> parts;
        public List<NameFormInfo> nameFormInfo;
    }

    public class NameFormInfo
    {
        public string order;
    }

    public class NonMatches
    {
        public string href;
    }

    public class Normalized
    {
        public string lang;
        public string value;
    }

    public class Notes
    {
        public string href;
    }

    public class Parent1
    {
        public string resource;
        public string resourceId;
        public string href;
    }

    public class Parent1Fact
    {
        public string id;
        public Attribution attribution;
        public string type;
        public Date date;
    }

    public class Parent2
    {
        public string resource;
        public string resourceId;
        public string href;
    }

    public class Parent2Fact
    {
        public string id;
        public Attribution attribution;
        public string type;
        public Date date;
    }

    public class Parents
    {
        public string href;
    }

    public class Part
    {
        public string type;
        public string value;
    }

    public class Person
    {
        public string id;
        public string sortKey;
        public List<Evidence> evidence;
        public bool living;
        public Gender gender;
        public Links links;
        public List<Source> sources;
        public Identifiers identifiers;
        public List<Name> names;
        public List<Fact> facts;
        public Display display;

        [JsonProperty("discussion-references")]
        public List<DiscussionReference> discussionreferences;
        public List<PersonInfo> personInfo;
    }

    public class Person1
    {
        public string resource;
        public string resourceId;
        public string href;
    }

    public class Person2
    {
        public string href;
    }

    public class Person22
    {
        public string resource;
        public string resourceId;
        public string href;
    }

    public class PersonInfo
    {
        public bool canUserEdit;
        public bool visibleToAll;
    }

    public class Place
    {
        public string original;
        public string description;
        public List<Normalized> normalized;
    }

    public class Place3
    {
        public string id;
        public double latitude;
        public double longitude;
        public List<Name> names;
    }

    public class Portrait
    {
        public string href;
    }

    public class Portraits
    {
        public string href;
    }

    public class Qualifier
    {
        public string value;
        public string name;
    }

    public class Relationship
    {
        public string id;
        public string sortKey;
        public string type;
        public Person1 person1;
        public Person2 person2;
        public Links links;
        public List<Source> sources;
        public List<Fact> facts;
        public Identifiers identifiers;
    }

    public class Relationship2
    {
        public string href;
    }

    public class AncestorInfoJson
    {
        public string description;
        public List<Person> persons;
        public List<Relationship> relationships;
        public List<SourceDescription> sourceDescriptions;
        public List<Place> places;
        public List<ChildAndParentsRelationship> childAndParentsRelationships;
    }

    public class Source
    {
        public string id;
        public Attribution attribution;
        public Links links;
        public string description;
        public string descriptionId;
        public List<Tag> tags;
    }

    public class SourceDescription
    {
        public string id;
        public string about;
        public ComponentOf componentOf;
        public string resourceType;
        public long modified;
        public string version;
        public Links links;
        public List<Citation> citations;
        public List<Title> titles;
        public Identifiers identifiers;
    }

    public class SourceDescriptions
    {
        public string href;
    }

    public class SourceReference
    {
        public string href;
    }

    public class Spouses
    {
        public string href;
    }

    public class Tag
    {
        public string resource;
    }

    public class Title
    {
        public string value;
    }
}
