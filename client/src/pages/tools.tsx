import { useState, useEffect } from "react";
import Sidebar from "@/components/layout/sidebar";
import SearchBar from "@/components/search-bar";
import StatusBar from "@/components/status-bar";
import Terminal from "@/components/terminal";
import ToolCard from "@/components/tool-card";
import { tools } from "@/data/tool-categories";
import { useTools } from "@/hooks/use-tools";
import { useTerminal } from "@/hooks/use-terminal";

export default function Tools() {
  const [selectedCategory, setSelectedCategory] = useState("vulnerability");
  const [searchTerm, setSearchTerm] = useState("");
  const [filteredTools, setFilteredTools] = useState(tools);
  const { addToolToRecents } = useTools();
  const { addInfoLine } = useTerminal();
  
  useEffect(() => {
    let result = tools;
    
    // Filter by category if one is selected
    if (selectedCategory) {
      result = result.filter(tool => tool.category === selectedCategory);
    }
    
    // Filter by search term if provided
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(
        tool => 
          tool.name.toLowerCase().includes(term) || 
          tool.description.toLowerCase().includes(term) ||
          tool.categoryLabel.toLowerCase().includes(term)
      );
    }
    
    setFilteredTools(result);
  }, [selectedCategory, searchTerm]);
  
  const handleCategorySelect = (category: string) => {
    setSelectedCategory(category);
  };
  
  const handleSearch = (term: string) => {
    setSearchTerm(term);
  };
  
  const handleReset = () => {
    setSearchTerm("");
    setSelectedCategory("vulnerability");
  };
  
  const handleUseTool = (tool: typeof tools[0]) => {
    addToolToRecents(tool);
    addInfoLine(`Initializing ${tool.name}...`);
  };
  
  // Get category name for display
  const getCategoryTitle = () => {
    const category = tools.find(t => t.category === selectedCategory);
    return category ? `${category.categoryLabel} Tools` : "Tools";
  };
  
  return (
    <div className="container mx-auto px-4 py-8">
      <StatusBar />
      
      <SearchBar 
        onSearch={handleSearch}
        onReset={handleReset}
      />
      
      <div className="flex flex-col lg:flex-row gap-6">
        <Sidebar 
          onCategorySelect={handleCategorySelect}
          selectedCategory={selectedCategory}
        />
        
        <div className="lg:w-3/4">
          <div className="bg-card rounded-md border border-secondary/30 mb-6">
            <div className="p-4 border-b border-secondary/30">
              <h2 className="text-secondary font-tech text-xl">{getCategoryTitle()}</h2>
            </div>
            
            <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredTools.length > 0 ? (
                filteredTools.map((tool) => (
                  <ToolCard
                    key={tool.id}
                    id={tool.id}
                    name={tool.name}
                    description={tool.description}
                    category={tool.category}
                    categoryLabel={tool.categoryLabel}
                    onUse={() => handleUseTool(tool)}
                  />
                ))
              ) : (
                <div className="col-span-3 text-center py-10 text-muted-foreground">
                  No tools found matching your criteria. Try adjusting your search or category selection.
                </div>
              )}
            </div>
          </div>
          
          <Terminal />
        </div>
      </div>
    </div>
  );
}
